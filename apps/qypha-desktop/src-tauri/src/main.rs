#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fs,
    io::SeekFrom,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::Mutex,
    time::{sleep, Duration, Instant},
};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "macos")]
use objc2_app_kit::{NSApplication, NSModalResponseOK, NSOpenPanel};
#[cfg(target_os = "macos")]
use objc2_foundation::{MainThreadMarker, NSString};

#[derive(Debug, Serialize)]
struct SecurityProfile {
    app: &'static str,
    mode_set: &'static [&'static str],
    key_policy: &'static str,
    message_persistence: &'static str,
    transfer_chunk_policy: &'static str,
    platform: &'static str,
    now_utc: String,
}

#[derive(Debug, Clone, Serialize)]
struct PeerSnapshot {
    name: String,
    did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_did: Option<String>,
    status: String,
    auto_reconnect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeadlessDirectPeerSnapshot {
    name: String,
    did: String,
    #[serde(default)]
    contact_did: Option<String>,
    #[serde(default)]
    canonical_did: Option<String>,
    peer_id: Option<String>,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxGroupSnapshot {
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    persistence: String,
    local_member_id: Option<String>,
    owner_member_id: Option<String>,
    owner_special_id: Option<String>,
    known_member_ids: Vec<String>,
    mailbox_epoch: u64,
    #[serde(default)]
    join_locked: bool,
    #[serde(default)]
    degraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupMailboxRuntimeEvent {
    kind: String,
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    manifest_id: Option<String>,
    sender_member_id: Option<String>,
    message: Option<String>,
    filename: Option<String>,
    size_bytes: Option<u64>,
    member_id: Option<String>,
    member_display_name: Option<String>,
    invite_code: Option<String>,
    mailbox_epoch: Option<u64>,
    kicked_member_id: Option<String>,
    #[serde(default)]
    ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectMessageRuntimeEvent {
    direction: String,
    peer_did: String,
    #[serde(default)]
    peer_contact_did: Option<String>,
    #[serde(default)]
    peer_canonical_did: Option<String>,
    peer_name: String,
    message: String,
    #[serde(default)]
    ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectPeerRuntimeEvent {
    event: String,
    did: String,
    #[serde(default)]
    contact_did: Option<String>,
    #[serde(default)]
    canonical_did: Option<String>,
    name: String,
    peer_id: Option<String>,
    status: String,
    reason: Option<String>,
    #[serde(default)]
    ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeadlessInviteResult {
    kind: String,
    code: Option<String>,
    error: Option<String>,
    group: Option<MailboxGroupSnapshot>,
}

const UI_BRIDGE_PREFIX: &str = "/ui ";

#[derive(Debug, Serialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HandshakeRequestPolicySnapshot {
    #[serde(default)]
    block_all: bool,
    #[serde(default)]
    blocked_member_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IncomingConnectPolicySnapshot {
    #[serde(default)]
    block_all: bool,
    #[serde(default)]
    blocked_dids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PendingContactRequestSnapshot {
    name: String,
    did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical_did: Option<String>,
    ts_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeSnapshot {
    running: bool,
    pid: Option<u32>,
    started_at: Option<String>,
    contact_did: Option<String>,
    selected_peer: Option<String>,
    last_error: Option<String>,
    mode: String,
    transport: String,
    listen_port: u16,
    peers: Vec<PeerSnapshot>,
    mailbox_groups: Vec<MailboxGroupSnapshot>,
    pending_approvals: Vec<String>,
    pending_contact_requests: Vec<PendingContactRequestSnapshot>,
    recent_logs: Vec<String>,
    transfer_events: Vec<TransferRuntimeEvent>,
    direct_events: Vec<DirectMessageRuntimeEvent>,
    peer_events: Vec<DirectPeerRuntimeEvent>,
    group_events: Vec<GroupMailboxRuntimeEvent>,
    handshake_request_policy: HandshakeRequestPolicySnapshot,
    incoming_connect_policy: IncomingConnectPolicySnapshot,
    latest_invite_code: Option<String>,
    latest_invite_revision: u64,
    latest_group_invite_code: Option<String>,
    latest_group_invite_revision: u64,
    receive_dir: Option<String>,
    ghost_handoffs: Vec<GhostHandoffSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentCard {
    name: String,
    agent_type: String,
    ai_provider: Option<String>,
    ai_model: Option<String>,
    ai_role: Option<String>,
    ai_access_mode: Option<String>,
    mode: String,
    transport: String,
    listen_port: u16,
    config_path: Option<String>,
    config_present: bool,
    running: bool,
    pid: Option<u32>,
    last_error: Option<String>,
    incoming_connect_block_all: bool,
    incoming_connect_policy_known: bool,
}

#[derive(Debug, Clone, Serialize)]
struct AppSnapshot {
    active_agent: Option<String>,
    agents: Vec<AgentCard>,
    runtime: Option<RuntimeSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeLineEvent {
    agent: String,
}

#[derive(Debug, Clone, Serialize)]
struct GhostRuntimeEvent {
    agent: String,
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct NamedGroupMailboxRuntimeEvent {
    agent: String,
    event: GroupMailboxRuntimeEvent,
}

#[derive(Debug, Default)]
struct IngestedRuntimeEvents {
    ghost_events: Vec<GhostRuntimeEvent>,
    direct_events: Vec<DirectMessageRuntimeEvent>,
    peer_events: Vec<DirectPeerRuntimeEvent>,
    group_events: Vec<GroupMailboxRuntimeEvent>,
}

impl std::ops::Deref for IngestedRuntimeEvents {
    type Target = [GhostRuntimeEvent];

    fn deref(&self) -> &Self::Target {
        &self.ghost_events
    }
}

#[derive(Debug, Clone, Serialize)]
struct GhostHandoffSnapshot {
    handoff_id: String,
    peer_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_contact_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_canonical_did: Option<String>,
    peer_name: String,
    filename: String,
    created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
struct TransferPickerSelection {
    path: String,
    is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferEventPayload {
    event: String,
    direction: String,
    #[serde(default)]
    peer_did: Option<String>,
    #[serde(default)]
    peer_name: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    handoff_id: Option<String>,
    #[serde(default)]
    handoff_path: Option<String>,
    #[serde(default)]
    transferred_chunks: Option<usize>,
    #[serde(default)]
    total_chunks: Option<usize>,
    #[serde(default)]
    transferred_bytes: Option<u64>,
    #[serde(default)]
    total_bytes: Option<u64>,
    #[serde(default)]
    percent: Option<u32>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    group_name: Option<String>,
    #[serde(default)]
    ts_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
struct TransferRuntimeEvent {
    agent: String,
    event: String,
    direction: String,
    peer_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_contact_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_canonical_did: Option<String>,
    peer_name: Option<String>,
    session_id: Option<String>,
    filename: Option<String>,
    reason: Option<String>,
    handoff_id: Option<String>,
    group_id: Option<String>,
    group_name: Option<String>,
    transferred_chunks: Option<usize>,
    total_chunks: Option<usize>,
    transferred_bytes: Option<u64>,
    total_bytes: Option<u64>,
    percent: Option<u32>,
    ts_ms: i64,
}

#[derive(Debug, Clone)]
struct AgentProfile {
    name: String,
    agent_type: DesktopAgentType,
    ai_provider: Option<String>,
    ai_model: Option<String>,
    ai_role: Option<String>,
    ai_access_mode: Option<String>,
    mode: String,
    transport: String,
    listen_port: u16,
    config_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum DesktopAgentType {
    #[default]
    Human,
    Ai,
}

impl DesktopAgentType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Ai => "ai",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentDesktopMetadata {
    name: String,
    #[serde(default)]
    agent_type: DesktopAgentType,
    #[serde(default)]
    ai_provider: Option<String>,
    #[serde(default)]
    ai_model: Option<String>,
    #[serde(default = "default_ai_role")]
    ai_role: String,
    #[serde(default = "default_ai_access_mode")]
    ai_access_mode: String,
    #[serde(default = "default_desktop_agent_log_mode")]
    log_mode: String,
    #[serde(default = "default_desktop_agent_transport")]
    transport: String,
    #[serde(default = "default_desktop_agent_listen_port")]
    listen_port: u16,
}

impl AgentDesktopMetadata {
    fn normalized(mut self) -> Self {
        self.name = self.name.trim().to_string();
        self.ai_provider = self
            .ai_provider
            .take()
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty());
        self.ai_model = self
            .ai_model
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.ai_role = normalize_ai_role_value(&self.ai_role);
        self.ai_access_mode = normalize_ai_access_mode_value(&self.ai_access_mode);
        self.log_mode = normalize_agent_mode(&self.log_mode)
            .unwrap_or_else(|| default_desktop_agent_log_mode());
        self.transport = normalize_agent_transport(&self.transport)
            .unwrap_or_else(|| default_desktop_agent_transport());
        self.listen_port = if self.listen_port == 0 {
            default_desktop_agent_listen_port()
        } else {
            self.listen_port
        };
        self
    }
}

fn default_ai_role() -> String {
    "general".to_string()
}

fn default_ai_access_mode() -> String {
    "full_access".to_string()
}

fn default_desktop_agent_log_mode() -> String {
    "safe".to_string()
}

fn default_desktop_agent_transport() -> String {
    "internet".to_string()
}

fn default_desktop_agent_listen_port() -> u16 {
    9090
}

fn is_desktop_listen_port_available(port: u16) -> bool {
    let bind_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
    let tcp_ok = std::net::TcpListener::bind(bind_addr).is_ok();
    let udp_ok = std::net::UdpSocket::bind(bind_addr).is_ok();
    tcp_ok && udp_ok
}

fn ensure_desktop_listen_port_available(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Listen port must be > 0".to_string());
    }
    if !is_desktop_listen_port_available(port) {
        return Err(format!(
            "Listen port {} is already in use (TCP or UDP)",
            port
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct AiProviderCatalog {
    ollama_host: String,
    ollama_models: Vec<AiModelOption>,
    ollama_available: bool,
    ollama_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct AiModelOption {
    id: String,
    label: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    #[serde(default)]
    models: Vec<OllamaTagModel>,
}

#[derive(Debug, Deserialize)]
struct OllamaTagModel {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AiAgentThreadMessage {
    role: String,
    content: String,
    ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AiAgentThreadState {
    ai_agent: String,
    requester_agent: Option<String>,
    ai_provider: Option<String>,
    ai_model: Option<String>,
    ai_role: String,
    ai_access_mode: String,
    messages: Vec<AiAgentThreadMessage>,
}

#[derive(Debug, Deserialize)]
struct LoadAiAgentThreadRequest {
    ai_agent: String,
    requester_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AiAgentChatRequest {
    ai_agent: String,
    requester_agent: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaChatMessage>,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: Option<OllamaChatMessage>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct PeerRuntime {
    name: String,
    did: String,
    contact_did: Option<String>,
    peer_id: Option<String>,
    status: String,
    auto_reconnect: bool,
}

#[derive(Debug, Clone)]
struct PendingContactRequestRuntime {
    name: String,
    did: String,
    contact_did: Option<String>,
    ts_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPeerListing {
    name: String,
    did: String,
    status: String,
    auto_reconnect: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingInviteKind {
    Direct,
    Group,
}

#[derive(Default)]
struct AgentRuntime {
    name: String,
    did: Option<String>,
    mode: String,
    transport: String,
    listen_port: u16,
    config_path: Option<String>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    started_at: Option<String>,
    selected_peer: Option<String>,
    launch_command: Option<String>,
    last_error: Option<String>,
    peers: HashMap<String, PeerRuntime>,
    pending_contact_requests: HashMap<String, PendingContactRequestRuntime>,
    pending_peers: Vec<PeerRuntime>,
    peer_refreshing: bool,
    peer_revision: u64,
    mailbox_groups: Vec<MailboxGroupSnapshot>,
    pending_mailbox_groups: Vec<MailboxGroupSnapshot>,
    mailbox_group_refreshing: bool,
    mailbox_group_revision: u64,
    pending_approvals: Vec<String>,
    pending_connected_peer_id: Option<String>,
    pending_verbose_name: Option<String>,
    pending_verbose_did: Option<String>,
    pending_verbose_peer_id: Option<String>,
    logs: VecDeque<String>,
    transfer_events: VecDeque<TransferRuntimeEvent>,
    direct_events: VecDeque<DirectMessageRuntimeEvent>,
    peer_events: VecDeque<DirectPeerRuntimeEvent>,
    group_events: VecDeque<GroupMailboxRuntimeEvent>,
    handshake_request_policy: HandshakeRequestPolicySnapshot,
    incoming_connect_policy: IncomingConnectPolicySnapshot,
    incoming_connect_policy_known: bool,
    transfer_event_file: Option<PathBuf>,
    latest_invite_code: Option<String>,
    latest_invite_revision: u64,
    latest_invite_error: Option<String>,
    latest_invite_error_revision: u64,
    latest_group_invite_code: Option<String>,
    latest_group_invite_revision: u64,
    latest_group_invite_error: Option<String>,
    latest_group_invite_error_revision: u64,
    receive_dir: Option<String>,
    receive_dir_revision: u64,
    ghost_handoffs: HashMap<String, GhostHandoff>,
    pending_invite_kind: Option<PendingInviteKind>,
    suppress_peer_listing_until_ms: u64,
    suppress_group_listing_until_ms: u64,
    command_gate: Arc<Mutex<()>>,
}

#[derive(Debug, Clone)]
struct GhostHandoff {
    handoff_id: String,
    peer_did: String,
    peer_name: String,
    filename: String,
    staged_path: PathBuf,
    created_at_ms: i64,
}

#[derive(Default)]
struct RuntimeManager {
    active_agent: Option<String>,
    runtimes: HashMap<String, AgentRuntime>,
}

fn sanitize_agent_name(agent_name: &str) -> String {
    agent_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

fn agent_contact_did_path(agent_name: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))?;
    Some(
        home.join(".qypha")
            .join("agents")
            .join(sanitize_agent_name(agent_name))
            .join("keys")
            .join("contact_did.txt"),
    )
}

fn read_agent_contact_did(agent_name: &str) -> Option<String> {
    let path = agent_contact_did_path(agent_name)?;
    let value = fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn canonical_did_from_contact_did(value: &str) -> Option<String> {
    let suffix = value.trim().strip_prefix("did:qypha:")?;
    let decoded = bs58::decode(suffix).into_vec().ok()?;
    if decoded.len() != 32 {
        return None;
    }
    Some(format!("did:nxf:{}", hex::encode(decoded)))
}

fn contact_did_from_canonical_did(value: &str) -> Option<String> {
    let suffix = value.trim().strip_prefix("did:nxf:")?;
    let decoded = hex::decode(suffix).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    Some(format!("did:qypha:{}", bs58::encode(decoded).into_string()))
}

fn resolve_canonical_did(
    visible_or_canonical: &str,
    explicit_canonical: Option<&str>,
) -> Option<String> {
    explicit_canonical
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| canonical_did_from_contact_did(visible_or_canonical.trim()))
        .or_else(|| {
            let trimmed = visible_or_canonical.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        })
}

fn resolve_contact_did(
    visible_or_canonical: &str,
    explicit_contact: Option<&str>,
    canonical_did: &str,
) -> Option<String> {
    explicit_contact
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| contact_did_from_canonical_did(canonical_did))
        .or_else(|| {
            let trimmed = visible_or_canonical.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        })
}

fn normalize_peer_selector(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    resolve_canonical_did(trimmed, None).unwrap_or_else(|| trimmed.to_string())
}

fn canonical_transfer_peer_did(event: &TransferRuntimeEvent) -> Option<&str> {
    event
        .peer_canonical_did
        .as_deref()
        .or(event.peer_did.as_deref())
}

#[derive(Clone)]
struct RuntimeState {
    inner: Arc<Mutex<RuntimeManager>>,
    shutdown_requested: Arc<AtomicBool>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RuntimeManager::default())),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Debug, Deserialize)]
struct StartRequest {
    config_path: Option<String>,
    agent_name: Option<String>,
    listen_port: Option<u16>,
    transport: Option<String>,
    log_mode: Option<String>,
    passphrase: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InitAgentRequest {
    name: String,
    transport: String,
    log_mode: String,
    listen_port: u16,
    passphrase: String,
    agent_type: Option<String>,
    ai_provider: Option<String>,
    ai_model: Option<String>,
    ai_role: Option<String>,
    ai_access_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AiProviderSecretRequest {
    provider: String,
    api_key: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiProviderSecretStatus {
    provider: String,
    provider_label: String,
    env_var_hint: Option<String>,
    configured: bool,
    storage_label: String,
}

#[derive(Debug, Clone, Serialize)]
struct AgentSkillRecord {
    id: String,
    name: String,
    file_path: String,
    markdown: String,
    updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
struct AgentSkillSaveRequest {
    agent_name: String,
    skill_id: Option<String>,
    name: String,
    markdown: String,
}

#[derive(Debug, Deserialize)]
struct AgentSkillDeleteRequest {
    agent_name: String,
    skill_id: String,
}

#[derive(Debug, Deserialize)]
struct PeerMessageRequest {
    peer: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TransferRequest {
    peer: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct AgentToml {
    agent: Option<AgentTomlAgent>,
    network: Option<AgentTomlNetwork>,
    security: Option<AgentTomlSecurity>,
    logging: Option<AgentTomlLogging>,
}

// Desktop only needs non-sensitive preview metadata from the config file.
// Sensitive transport/mailbox fields may be ENC: blobs and are intentionally
// ignored here so UI discovery stays passphrase-free.

#[derive(Debug, Deserialize)]
struct AgentTomlAgent {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlNetwork {
    listen_port: Option<u16>,
    transport_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlSecurity {
    log_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlLogging {
    mode: Option<String>,
}

#[tauri::command]
fn app_security_profile() -> SecurityProfile {
    SecurityProfile {
        app: "Qypha",
        mode_set: &["safe", "ghost"],
        key_policy: "ghost => in-memory ephemeral keys; safe => persistent encrypted keys",
        message_persistence:
            "ghost => zero-persist session memory, safe => privacy-hardened encrypted storage",
        transfer_chunk_policy: "disk-staged chunks allowed (receiver approval + secure wipe)",
        platform: std::env::consts::OS,
        now_utc: Utc::now().to_rfc3339(),
    }
}

#[tauri::command]
async fn list_ai_provider_catalog() -> Result<AiProviderCatalog, String> {
    let ollama_host = normalized_ollama_host();
    let mut models = configured_ollama_cloud_models()
        .into_iter()
        .map(|name| AiModelOption {
            id: name.clone(),
            label: name,
            source: "cloud".to_string(),
        })
        .collect::<Vec<_>>();

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?
        .get(format!("{}/api/tags", ollama_host.trim_end_matches('/')))
        .send()
        .await;

    let mut ollama_available = false;
    let mut ollama_error = None;
    match response {
        Ok(response) => {
            if response.status().is_success() {
                let payload = response
                    .json::<OllamaTagsResponse>()
                    .await
                    .map_err(|error| format!("Failed to decode Ollama tags response: {error}"))?;
                for model in payload.models {
                    let name = model.name.trim().to_string();
                    if name.is_empty() || models.iter().any(|entry| entry.id == name) {
                        continue;
                    }
                    models.push(AiModelOption {
                        id: name.clone(),
                        label: name,
                        source: "local".to_string(),
                    });
                }
                ollama_available = true;
            } else {
                ollama_error = Some(format!("Ollama returned HTTP {}", response.status()));
            }
        }
        Err(error) => {
            ollama_error = Some(error.to_string());
        }
    }

    models.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.source.cmp(&b.source)));

    Ok(AiProviderCatalog {
        ollama_host,
        ollama_models: models,
        ollama_available,
        ollama_error,
    })
}

#[tauri::command]
fn get_ai_provider_secret_status(provider: String) -> Result<AiProviderSecretStatus, String> {
    let normalized = normalize_desktop_ai_provider(&provider)
        .ok_or_else(|| format!("Unsupported AI provider: {}", provider.trim()))?;
    Ok(read_ai_provider_secret_status(normalized))
}

#[tauri::command]
fn set_ai_provider_secret(req: AiProviderSecretRequest) -> Result<AiProviderSecretStatus, String> {
    let normalized = normalize_desktop_ai_provider(&req.provider)
        .ok_or_else(|| format!("Unsupported AI provider: {}", req.provider.trim()))?;
    let secret = req.api_key.trim();
    if secret.is_empty() {
        return Err("API key is required".to_string());
    }
    ai_provider_secret_entry(normalized)?
        .set_password(secret)
        .map_err(|error| {
            format!(
                "Failed to store {} credential: {error}",
                provider_label(normalized)
            )
        })?;
    Ok(read_ai_provider_secret_status(normalized))
}

#[tauri::command]
fn delete_ai_provider_secret(provider: String) -> Result<AiProviderSecretStatus, String> {
    let normalized = normalize_desktop_ai_provider(&provider)
        .ok_or_else(|| format!("Unsupported AI provider: {}", provider.trim()))?;
    let entry = ai_provider_secret_entry(normalized)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(read_ai_provider_secret_status(normalized)),
        Err(error) => Err(format!(
            "Failed to remove {} credential: {error}",
            provider_label(normalized)
        )),
    }
}

#[tauri::command]
fn list_agent_skills(agent_name: String) -> Result<Vec<AgentSkillRecord>, String> {
    let root = workspace_root();
    let trimmed_agent = agent_name.trim();
    if trimmed_agent.is_empty() {
        return Ok(Vec::new());
    }
    read_agent_skill_records(&root, trimmed_agent)
}

#[tauri::command]
fn save_agent_skill(req: AgentSkillSaveRequest) -> Result<AgentSkillRecord, String> {
    let root = workspace_root();
    let trimmed_agent = req.agent_name.trim();
    if trimmed_agent.is_empty() {
        return Err("Agent name is required".to_string());
    }
    let trimmed_name = req.name.trim();
    if trimmed_name.is_empty() {
        return Err("Skill name is required".to_string());
    }
    let stripped_markdown = split_skill_frontmatter(&req.markdown).2;
    if stripped_markdown.trim().is_empty() {
        return Err("Skill markdown is required".to_string());
    }

    let skills_root = agent_skills_root_path(&root, trimmed_agent);
    ensure_private_dir_local(&skills_root)?;

    let skill_id = match req
        .skill_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(existing) => sanitized_skill_identifier(existing),
        None => unique_skill_identifier(&skills_root, trimmed_name),
    };
    let skill_dir = agent_skill_dir_path(&root, trimmed_agent, &skill_id);
    ensure_private_dir_local(&skill_dir)?;
    let markdown_path = agent_skill_markdown_path(&root, trimmed_agent, &skill_id);
    let content = build_agent_skill_markdown(trimmed_name, &stripped_markdown);
    fs::write(&markdown_path, content)
        .map_err(|error| format!("Failed to save skill '{}': {}", trimmed_name, error))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&markdown_path, fs::Permissions::from_mode(0o600));
    }

    read_agent_skill_record(&skill_dir)?.ok_or_else(|| "Failed to reload saved skill".to_string())
}

#[tauri::command]
fn delete_agent_skill(req: AgentSkillDeleteRequest) -> Result<Vec<AgentSkillRecord>, String> {
    let root = workspace_root();
    let trimmed_agent = req.agent_name.trim();
    if trimmed_agent.is_empty() {
        return Err("Agent name is required".to_string());
    }
    let trimmed_skill_id = req.skill_id.trim();
    if trimmed_skill_id.is_empty() {
        return Err("Skill id is required".to_string());
    }
    let skill_dir = agent_skill_dir_path(&root, trimmed_agent, trimmed_skill_id);
    if skill_dir.exists() {
        secure_wipe_dir_local(&skill_dir)?;
    }
    read_agent_skill_records(&root, trimmed_agent)
}

#[tauri::command]
async fn agent_init(
    state: State<'_, RuntimeState>,
    req: InitAgentRequest,
) -> Result<AppSnapshot, String> {
    const MIN_SAFE_PASSPHRASE_LEN: usize = 4;
    let agent_name = req.name.trim().to_string();
    if agent_name.is_empty() {
        return Err("Agent name is required".to_string());
    }
    let agent_type = normalize_agent_type(req.agent_type.as_deref().unwrap_or("human"))
        .ok_or_else(|| "Invalid agent type. Use human or ai.".to_string())?;

    let root = workspace_root();
    let metadata = AgentDesktopMetadata {
        name: agent_name.clone(),
        agent_type,
        ai_provider: req.ai_provider.clone(),
        ai_model: req.ai_model.clone(),
        ai_role: req.ai_role.clone().unwrap_or_else(default_ai_role),
        ai_access_mode: req
            .ai_access_mode
            .clone()
            .unwrap_or_else(default_ai_access_mode),
        log_mode: req.log_mode.trim().to_lowercase(),
        transport: req.transport.trim().to_lowercase(),
        listen_port: req.listen_port,
    }
    .normalized();

    if matches!(agent_type, DesktopAgentType::Human) {
        ensure_desktop_listen_port_available(req.listen_port)?;
        if req.log_mode.eq_ignore_ascii_case("ghost") {
            return Err(
                "Ghost mode does not create persistent agents. Use Start with mode=ghost + transport=tor."
                    .to_string(),
            );
        }
        if !req.log_mode.eq_ignore_ascii_case("safe") {
            return Err("Invalid mode. Persistent agent creation supports only safe.".to_string());
        }
        let transport = normalize_agent_transport(&req.transport)
            .ok_or_else(|| "Invalid transport. Use tcp, tor, or internet.".to_string())?;
        if req.passphrase.trim().len() < MIN_SAFE_PASSPHRASE_LEN {
            return Err(format!(
                "Passphrase too short (minimum {} characters)",
                MIN_SAFE_PASSPHRASE_LEN
            ));
        }

        let args = vec![
            "init".to_string(),
            "--name".to_string(),
            agent_name.clone(),
            "--transport".to_string(),
            transport.clone(),
            "--log-mode".to_string(),
            req.log_mode.trim().to_lowercase(),
            "--port".to_string(),
            req.listen_port.to_string(),
        ];
        let (mut cmd, command_desc) = build_qypha_command(&root, args)?;
        cmd.current_dir(&root)
            .env("QYPHA_INIT_PASSPHRASE", req.passphrase.clone())
            .env("QYPHA_CONFIG_PASSPHRASE", req.passphrase)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd
            .output()
            .await
            .map_err(|e| format!("Agent init failed to start: {}", e))?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "FAILED: {}\n{}\n{}",
                command_desc,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }

    save_agent_desktop_metadata(&root, &agent_name, &metadata)
        .map_err(|error| format!("Failed to save agent profile metadata: {error}"))?;

    let mut manager = state.inner.lock().await;
    let profile = AgentProfile {
        name: agent_name.clone(),
        agent_type,
        ai_provider: metadata.ai_provider.clone(),
        ai_model: metadata.ai_model.clone(),
        ai_role: Some(metadata.ai_role.clone()),
        ai_access_mode: Some(metadata.ai_access_mode.clone()),
        mode: metadata.log_mode.clone(),
        transport: metadata.transport.clone(),
        listen_port: metadata.listen_port,
        config_path: if matches!(agent_type, DesktopAgentType::Ai) {
            None
        } else {
            Some(
                derived_agent_config_path(&root, &agent_name)
                    .display()
                    .to_string(),
            )
        },
    };
    let runtime = manager.runtimes.entry(profile.name.clone()).or_default();
    runtime.name = profile.name.clone();
    runtime.mode = profile.mode.clone();
    runtime.transport = profile.transport.clone();
    runtime.listen_port = profile.listen_port;
    runtime.config_path = profile.config_path.clone();
    push_log(
        runtime,
        format!(
            "[qypha] agent initialized: {} ({}, {}, port {})",
            profile.name,
            profile.mode,
            display_transport_label(&profile.transport),
            profile.listen_port
        ),
    );
    manager.active_agent = Some(profile.name.clone());
    let _ = save_persisted_active_agent(&root, &profile.name);

    refresh_all_runtimes(&mut manager).await;
    let profiles = discover_agent_profiles(&root);
    Ok(build_app_snapshot(&manager, &profiles))
}

#[tauri::command]
async fn load_ai_agent_thread(req: LoadAiAgentThreadRequest) -> Result<AiAgentThreadState, String> {
    let root = workspace_root();
    let ai_agent = req.ai_agent.trim().to_string();
    if ai_agent.is_empty() {
        return Err("AI agent name is required".to_string());
    }
    let metadata_path = agent_metadata_path(&root, &ai_agent);
    let metadata = load_agent_desktop_metadata(&metadata_path)
        .ok_or_else(|| format!("AI agent '{}' not found", ai_agent))?;
    if metadata.agent_type != DesktopAgentType::Ai {
        return Err(format!("Agent '{}' is not an AI agent", ai_agent));
    }
    let requester = req
        .requester_agent
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    Ok(load_ai_agent_thread_state(&root, &metadata, requester))
}

#[tauri::command]
async fn ai_agent_send_message(req: AiAgentChatRequest) -> Result<AiAgentThreadState, String> {
    let root = workspace_root();
    let ai_agent = req.ai_agent.trim().to_string();
    let message = req.message.trim().to_string();
    if ai_agent.is_empty() {
        return Err("AI agent name is required".to_string());
    }
    if message.is_empty() {
        return Err("Message is required".to_string());
    }

    let metadata_path = agent_metadata_path(&root, &ai_agent);
    let metadata = load_agent_desktop_metadata(&metadata_path)
        .ok_or_else(|| format!("AI agent '{}' not found", ai_agent))?;
    if metadata.agent_type != DesktopAgentType::Ai {
        return Err(format!("Agent '{}' is not an AI agent", ai_agent));
    }

    let provider = metadata
        .ai_provider
        .as_deref()
        .unwrap_or("ollama")
        .trim()
        .to_lowercase();
    if provider != "ollama" {
        return Err(format!(
            "{} runtime wiring is not ready yet. Ollama is the first live provider.",
            provider_label(&provider)
        ));
    }
    let model = metadata
        .ai_model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("AI agent '{}' has no Ollama model selected", ai_agent))?
        .to_string();
    let requester = req
        .requester_agent
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let mut thread = load_ai_agent_thread_state(&root, &metadata, requester);
    thread.messages.push(AiAgentThreadMessage {
        role: "user".to_string(),
        content: message,
        ts_ms: Utc::now().timestamp_millis(),
    });
    if thread.messages.len() > 80 {
        let overflow = thread.messages.len().saturating_sub(80);
        thread.messages.drain(0..overflow);
    }

    let mut ollama_messages = Vec::with_capacity(thread.messages.len() + 1);
    ollama_messages.push(OllamaChatMessage {
        role: "system".to_string(),
        content: build_ai_agent_system_prompt(&metadata),
    });
    ollama_messages.extend(thread.messages.iter().map(|entry| OllamaChatMessage {
        role: entry.role.clone(),
        content: entry.content.clone(),
    }));

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|error| format!("Failed to create Ollama client: {error}"))?
        .post(format!(
            "{}/api/chat",
            normalized_ollama_host().trim_end_matches('/')
        ))
        .json(&OllamaChatRequest {
            model,
            messages: ollama_messages,
            stream: false,
        })
        .send()
        .await
        .map_err(|error| format!("Failed to reach Ollama: {error}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Ollama chat failed with HTTP {status}: {}",
            body.trim()
        ));
    }

    let payload = response
        .json::<OllamaChatResponse>()
        .await
        .map_err(|error| format!("Failed to decode Ollama response: {error}"))?;
    if let Some(error) = payload.error.filter(|value| !value.trim().is_empty()) {
        return Err(format!("Ollama error: {}", error.trim()));
    }
    let assistant_message = payload
        .message
        .and_then(|message| {
            let content = message.content.trim().to_string();
            if content.is_empty() {
                None
            } else {
                Some(content)
            }
        })
        .ok_or_else(|| "Ollama returned an empty assistant response".to_string())?;

    thread.messages.push(AiAgentThreadMessage {
        role: "assistant".to_string(),
        content: assistant_message,
        ts_ms: Utc::now().timestamp_millis(),
    });
    if thread.messages.len() > 120 {
        let overflow = thread.messages.len().saturating_sub(120);
        thread.messages.drain(0..overflow);
    }

    save_ai_agent_thread_state(&root, &thread)?;
    Ok(thread)
}

#[tauri::command]
async fn runtime_select_agent(
    state: State<'_, RuntimeState>,
    agent_name: String,
) -> Result<AppSnapshot, String> {
    let target = agent_name.trim().to_string();
    if target.is_empty() {
        return Err("Agent name is required".to_string());
    }
    let root = workspace_root();
    let profiles = discover_agent_profiles(&root);

    let mut manager = state.inner.lock().await;
    if !manager.runtimes.contains_key(&target) {
        if let Some(profile) = profiles.iter().find(|p| p.name == target) {
            manager
                .runtimes
                .insert(target.clone(), runtime_from_profile(profile));
        } else {
            return Err(format!("Agent '{}' not found", target));
        }
    }
    manager.active_agent = Some(target.clone());
    let _ = save_persisted_active_agent(&root, &target);
    refresh_all_runtimes(&mut manager).await;
    Ok(build_app_snapshot(&manager, &profiles))
}

#[tauri::command]
async fn runtime_start(
    app: tauri::AppHandle,
    state: State<'_, RuntimeState>,
    req: StartRequest,
) -> Result<AppSnapshot, String> {
    const MIN_SAFE_PASSPHRASE_LEN: usize = 4;
    let root = workspace_root();
    let mut manager = state.inner.lock().await;
    refresh_all_runtimes(&mut manager).await;

    let agent_name = req
        .agent_name
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Agent name is required".to_string())?;
    let log_mode = req.log_mode.unwrap_or_else(|| "safe".to_string());
    if !matches!(log_mode.trim().to_lowercase().as_str(), "safe" | "ghost") {
        return Err("Invalid mode. Use safe or ghost.".to_string());
    }
    let log_mode = normalize_agent_mode(&log_mode)
        .ok_or_else(|| "Invalid mode. Use safe or ghost.".to_string())?;
    let transport = req
        .transport
        .unwrap_or_else(|| "internet".to_string())
        .to_lowercase();
    let transport = normalize_agent_transport(&transport)
        .ok_or_else(|| "Invalid transport. Use tcp, tor, or internet.".to_string())?;
    let listen_port = req.listen_port.unwrap_or(9090);
    ensure_desktop_listen_port_available(listen_port)?;
    let derived_config_path = derived_agent_config_path(&root, &agent_name);
    let requested_config_path = req
        .config_path
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    {
        let runtime = manager.runtimes.entry(agent_name.clone()).or_default();
        if runtime.child.is_some() {
            return Err(format!("Agent '{}' is already running", agent_name));
        }
        runtime.name = agent_name.clone();
        runtime.mode = log_mode.clone();
        runtime.transport = transport.clone();
        runtime.listen_port = listen_port;
        if log_mode != "ghost" {
            runtime.config_path = Some(derived_config_path.display().to_string());
            if let Some(requested_path) = requested_config_path.as_ref() {
                if requested_path != &derived_config_path {
                    push_log(
                        runtime,
                        format!(
                            "[qypha] ignoring UI config path override; using {}",
                            derived_config_path.display()
                        ),
                    );
                }
            }
        } else {
            runtime.config_path = None;
        }
    }

    let mut envs: Vec<(String, String)> = vec![("QYPHA_HEADLESS".to_string(), "1".to_string())];
    let transfer_event_file = create_transfer_event_sidechannel(&agent_name)?;
    envs.push((
        "QYPHA_TRANSFER_EVENT_FILE".to_string(),
        transfer_event_file.display().to_string(),
    ));

    // All modes use `launch` command — it auto-creates agent if needed,
    // or reuses existing config if already initialized.
    if log_mode == "ghost" {
        if transport != "tor" {
            return Err("Ghost mode requires Tor transport".to_string());
        }
        envs.push(("QYPHA_GHOST_SECURE_HANDOFF".to_string(), "1".to_string()));
    } else {
        // Non-ghost modes require a passphrase for key encryption
        let passphrase = req
            .passphrase
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Passphrase is required for safe mode".to_string())?;
        if passphrase.len() < MIN_SAFE_PASSPHRASE_LEN {
            return Err(format!(
                "Passphrase too short (minimum {} characters)",
                MIN_SAFE_PASSPHRASE_LEN
            ));
        }

        // QYPHA_PASSPHRASE  — unlocks existing agent keys (start_daemon)
        // QYPHA_INIT_PASSPHRASE — encrypts new keys (initialize_agent)
        // QYPHA_CONFIG_PASSPHRASE — decrypts sensitive ENC: config fields pre-daemon
        // Both are set so `launch` works for new AND existing agents.
        envs.push(("QYPHA_PASSPHRASE".to_string(), passphrase.clone()));
        envs.push(("QYPHA_CONFIG_PASSPHRASE".to_string(), passphrase.clone()));
        envs.push(("QYPHA_INIT_PASSPHRASE".to_string(), passphrase));
    }

    let args = vec![
        "launch".to_string(),
        "--name".to_string(),
        agent_name.clone(),
        "--transport".to_string(),
        transport.clone(),
        "--log-mode".to_string(),
        log_mode.clone(),
        "--port".to_string(),
        listen_port.to_string(),
    ];

    let (mut cmd, command_desc) = build_qypha_command(&root, args)?;
    cmd.current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to start agent '{}': {}", agent_name, e))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdin = child.stdin.take();

    {
        let runtime = manager.runtimes.get_mut(&agent_name).unwrap();
        runtime.child = Some(child);
        runtime.stdin = stdin;
        runtime.started_at = Some(Utc::now().to_rfc3339());
        runtime.launch_command = Some(command_desc);
        runtime.last_error = None;
        runtime.transfer_event_file = Some(transfer_event_file.clone());
        runtime.peers.clear();
        runtime.did = None;
        clear_pending_verbose_peer(runtime);
        runtime.pending_approvals.clear();
        push_log(runtime, "[qypha] runtime started".to_string());
    }
    manager.active_agent = Some(agent_name.clone());
    let _ = save_persisted_active_agent(&root, &agent_name);

    if let Some(out) = stdout {
        let manager_for_stdout = state.inner.clone();
        let app_for_stdout = app.clone();
        let agent_key = agent_name.clone();
        tokio::spawn(async move {
            pump_runtime_stream(out, manager_for_stdout, app_for_stdout, agent_key, false).await;
        });
    }
    if let Some(err) = stderr {
        let manager_for_stderr = state.inner.clone();
        let app_for_stderr = app.clone();
        let agent_key = agent_name.clone();
        tokio::spawn(async move {
            pump_runtime_stream(err, manager_for_stderr, app_for_stderr, agent_key, true).await;
        });
    }

    {
        let manager_for_transfer = state.inner.clone();
        let app_for_transfer = app.clone();
        let agent_key = agent_name.clone();
        tokio::spawn(async move {
            pump_transfer_event_file(
                manager_for_transfer,
                app_for_transfer,
                agent_key,
                transfer_event_file,
            )
            .await;
        });
    }

    let profiles = discover_agent_profiles(&root);
    Ok(build_app_snapshot(&manager, &profiles))
}

#[tauri::command]
async fn runtime_stop(
    state: State<'_, RuntimeState>,
    agent: Option<String>,
) -> Result<AppSnapshot, String> {
    let root = workspace_root();
    let mut manager = state.inner.lock().await;
    refresh_all_runtimes(&mut manager).await;

    let target = agent
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| manager.active_agent.clone())
        .ok_or_else(|| "No active agent selected".to_string())?;

    let runtime = manager
        .runtimes
        .get_mut(&target)
        .ok_or_else(|| format!("Agent '{}' not found", target))?;

    if runtime.child.is_none() {
        let profiles = discover_agent_profiles(&root);
        return Ok(build_app_snapshot(&manager, &profiles));
    }

    stop_runtime_process(runtime).await?;

    let profiles = discover_agent_profiles(&root);
    Ok(build_app_snapshot(&manager, &profiles))
}

#[tauri::command]
async fn runtime_destroy_agent(
    state: State<'_, RuntimeState>,
    agent: Option<String>,
) -> Result<AppSnapshot, String> {
    let root = workspace_root();
    let target_metadata = agent
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|name| agent_metadata_path(&root, &name));
    let target = {
        let mut manager = state.inner.lock().await;
        refresh_all_runtimes(&mut manager).await;
        let target = agent
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| manager.active_agent.clone())
            .ok_or_else(|| "No agent selected".to_string())?;
        if let Some(runtime) = manager.runtimes.get_mut(&target) {
            stop_runtime_process(runtime).await?;
        }
        manager.runtimes.remove(&target);
        if manager.active_agent.as_deref() == Some(target.as_str()) {
            manager.active_agent = None;
        }
        target
    };

    let metadata_path = target_metadata.unwrap_or_else(|| agent_metadata_path(&root, &target));
    let metadata = load_agent_desktop_metadata(&metadata_path);
    let is_ai_profile = metadata
        .as_ref()
        .map(|entry| entry.agent_type == DesktopAgentType::Ai)
        .unwrap_or(false);

    if is_ai_profile {
        secure_wipe_ai_agent_workspace_state(&root, &target);
        let profiles = discover_agent_profiles(&root);
        let mut manager = state.inner.lock().await;
        apply_preferred_active_agent(&root, &mut manager, &profiles);
        refresh_all_runtimes(&mut manager).await;
        return Ok(build_app_snapshot(&manager, &profiles));
    }

    let args = vec![
        "destroy".to_string(),
        "--name".to_string(),
        target.clone(),
        "--force".to_string(),
    ];
    let (mut cmd, command_desc) = build_qypha_command(&root, args)?;
    cmd.current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to destroy agent '{}': {}", target, e))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "FAILED: {}\n{}\n{}",
            command_desc,
            stdout.trim(),
            stderr.trim()
        ));
    }
    secure_wipe_ai_agent_workspace_state(&root, &target);

    let profiles = discover_agent_profiles(&root);
    let mut manager = state.inner.lock().await;
    apply_preferred_active_agent(&root, &mut manager, &profiles);
    refresh_all_runtimes(&mut manager).await;
    Ok(build_app_snapshot(&manager, &profiles))
}

#[tauri::command]
async fn runtime_destroy_all_agents(state: State<'_, RuntimeState>) -> Result<AppSnapshot, String> {
    let root = workspace_root();
    {
        let mut manager = state.inner.lock().await;
        refresh_all_runtimes(&mut manager).await;
        let names = manager.runtimes.keys().cloned().collect::<Vec<_>>();
        for name in names {
            if let Some(runtime) = manager.runtimes.get_mut(&name) {
                stop_runtime_process(runtime).await?;
            }
        }
        manager.runtimes.clear();
        manager.active_agent = None;
    }

    let args = vec!["destroy-all".to_string(), "--force".to_string()];
    let (mut cmd, command_desc) = build_qypha_command(&root, args)?;
    cmd.current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to destroy all agents: {}", e))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "FAILED: {}\n{}\n{}",
            command_desc,
            stdout.trim(),
            stderr.trim()
        ));
    }

    secure_wipe_all_ai_workspace_state(&root);

    let profiles = discover_agent_profiles(&root);
    let mut manager = state.inner.lock().await;
    manager.runtimes.clear();
    manager.active_agent = None;
    let _ = clear_persisted_active_agent(&root);
    Ok(build_app_snapshot(&manager, &profiles))
}

#[tauri::command]
async fn runtime_snapshot(state: State<'_, RuntimeState>) -> Result<AppSnapshot, String> {
    Ok(build_runtime_snapshot_response(state.inner()).await)
}

async fn build_runtime_snapshot_response(state: &RuntimeState) -> AppSnapshot {
    let root = workspace_root();
    let mut manager = state.inner.lock().await;
    refresh_all_runtimes(&mut manager).await;
    let profiles = discover_agent_profiles(&root);
    apply_preferred_active_agent(&root, &mut manager, &profiles);
    build_app_snapshot(&manager, &profiles)
}

#[tauri::command]
async fn runtime_refresh_peers(state: State<'_, RuntimeState>) -> Result<(), String> {
    let _ = runtime_list_peers(state).await?;
    Ok(())
}

#[tauri::command]
async fn runtime_refresh_groups(state: State<'_, RuntimeState>) -> Result<(), String> {
    let _ = runtime_list_groups(state).await?;
    Ok(())
}

fn invite_state(runtime: &AgentRuntime, kind: PendingInviteKind) -> (u64, Option<String>) {
    match kind {
        PendingInviteKind::Direct => (
            runtime.latest_invite_revision,
            runtime.latest_invite_code.clone(),
        ),
        PendingInviteKind::Group => (
            runtime.latest_group_invite_revision,
            runtime.latest_group_invite_code.clone(),
        ),
    }
}

fn invite_error_state(runtime: &AgentRuntime, kind: PendingInviteKind) -> (u64, Option<String>) {
    match kind {
        PendingInviteKind::Direct => (
            runtime.latest_invite_error_revision,
            runtime.latest_invite_error.clone(),
        ),
        PendingInviteKind::Group => (
            runtime.latest_group_invite_error_revision,
            runtime.latest_group_invite_error.clone(),
        ),
    }
}

async fn wait_for_peer_refresh(
    state: &RuntimeState,
    agent_name: &str,
    previous_revision: u64,
) -> Result<Vec<PeerSnapshot>, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        {
            let manager = state.inner.lock().await;
            let runtime = manager
                .runtimes
                .get(agent_name)
                .ok_or_else(|| format!("Runtime '{}' not found", agent_name))?;
            if runtime.peer_revision > previous_revision {
                let peers = snapshot_from_runtime(runtime, 64).peers;
                return Ok(peers);
            }
            if runtime.child.is_none() {
                return Err(format!(
                    "Runtime '{}' stopped before peers were refreshed",
                    agent_name
                ));
            }
            if Instant::now() >= deadline {
                return Ok(snapshot_from_runtime(runtime, 64).peers);
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_group_refresh(
    state: &RuntimeState,
    agent_name: &str,
    previous_revision: u64,
) -> Result<Vec<MailboxGroupSnapshot>, String> {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        {
            let manager = state.inner.lock().await;
            let runtime = manager
                .runtimes
                .get(agent_name)
                .ok_or_else(|| format!("Runtime '{}' not found", agent_name))?;
            if runtime.mailbox_group_revision > previous_revision {
                return Ok(runtime.mailbox_groups.clone());
            }
            if runtime.child.is_none() {
                return Err(format!(
                    "Runtime '{}' stopped before groups were refreshed",
                    agent_name
                ));
            }
            if Instant::now() >= deadline {
                return Ok(runtime.mailbox_groups.clone());
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_receive_dir_refresh(
    state: &RuntimeState,
    agent_name: &str,
    previous_revision: u64,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        {
            let manager = state.inner.lock().await;
            let runtime = manager
                .runtimes
                .get(agent_name)
                .ok_or_else(|| format!("Runtime '{}' not found", agent_name))?;
            if runtime.receive_dir_revision > previous_revision {
                if let Some(path) = runtime
                    .receive_dir
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    return Ok(path.to_string());
                }
            }
            if runtime.child.is_none() {
                return Err(format!(
                    "Runtime '{}' stopped before receive dir was refreshed",
                    agent_name
                ));
            }
            if Instant::now() >= deadline {
                if let Some(path) = runtime
                    .receive_dir
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    return Ok(path.to_string());
                }
                return Err("Receive dir not reported yet".to_string());
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn runtime_list_peers_with_gate_held(state: &RuntimeState) -> Result<AppSnapshot, String> {
    let (agent_name, previous_revision, pending_invite) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let pending_invite = runtime.pending_invite_kind.is_some();
        let previous_revision = runtime.peer_revision;
        if !pending_invite {
            runtime.suppress_peer_listing_until_ms =
                (Utc::now().timestamp_millis().max(0) as u64).saturating_add(3_000);
            send_line_silent(runtime, "/all").await?;
        }
        (runtime.name.clone(), previous_revision, pending_invite)
    };
    if pending_invite {
        return Ok(build_runtime_snapshot_response(state).await);
    }
    let _ = wait_for_peer_refresh(state, &agent_name, previous_revision).await?;
    Ok(build_runtime_snapshot_response(state).await)
}

#[tauri::command]
async fn runtime_list_peers(state: State<'_, RuntimeState>) -> Result<AppSnapshot, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    runtime_list_peers_with_gate_held(state.inner()).await
}

#[tauri::command]
async fn runtime_try_list_peers(state: State<'_, RuntimeState>) -> Result<AppSnapshot, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let Ok(_command_guard) = gate.try_lock() else {
        return Ok(build_runtime_snapshot_response(state.inner()).await);
    };
    runtime_list_peers_with_gate_held(state.inner()).await
}

async fn runtime_list_groups_with_gate_held(state: &RuntimeState) -> Result<AppSnapshot, String> {
    let (agent_name, previous_revision, pending_invite) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let pending_invite = runtime.pending_invite_kind.is_some();
        let previous_revision = runtime.mailbox_group_revision;
        if !pending_invite {
            runtime.suppress_group_listing_until_ms =
                (Utc::now().timestamp_millis().max(0) as u64).saturating_add(3_000);
            send_line_silent(runtime, "/groups").await?;
        }
        (runtime.name.clone(), previous_revision, pending_invite)
    };
    if pending_invite {
        return Ok(build_runtime_snapshot_response(state).await);
    }
    let _ = wait_for_group_refresh(state, &agent_name, previous_revision).await?;
    Ok(build_runtime_snapshot_response(state).await)
}

#[tauri::command]
async fn runtime_list_groups(state: State<'_, RuntimeState>) -> Result<AppSnapshot, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    runtime_list_groups_with_gate_held(state.inner()).await
}

#[tauri::command]
async fn runtime_try_list_groups(state: State<'_, RuntimeState>) -> Result<AppSnapshot, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let Ok(_command_guard) = gate.try_lock() else {
        return Ok(build_runtime_snapshot_response(state.inner()).await);
    };
    runtime_list_groups_with_gate_held(state.inner()).await
}

async fn wait_for_invite_capture(
    state: &RuntimeState,
    agent_name: &str,
    kind: PendingInviteKind,
    previous_revision: u64,
    previous_error_revision: u64,
) -> Result<String, String> {
    let deadline = Instant::now()
        + match kind {
            PendingInviteKind::Direct => Duration::from_secs(10),
            PendingInviteKind::Group => Duration::from_secs(20),
        };
    loop {
        {
            let mut manager = state.inner.lock().await;
            let runtime = manager
                .runtimes
                .get_mut(agent_name)
                .ok_or_else(|| format!("Runtime '{}' not found", agent_name))?;
            let (revision, code) = invite_state(runtime, kind);
            if revision > previous_revision {
                if let Some(code) = code
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                {
                    return Ok(code);
                }
            }
            let (error_revision, error_message) = invite_error_state(runtime, kind);
            if error_revision > previous_error_revision {
                if let Some(error_message) = error_message
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                {
                    runtime.pending_invite_kind = None;
                    return Err(error_message);
                }
            }
            if runtime.child.is_none() {
                runtime.pending_invite_kind = None;
                return Err(format!(
                    "Runtime '{}' stopped before invite was captured",
                    agent_name
                ));
            }
            if Instant::now() >= deadline {
                runtime.pending_invite_kind = None;
                return Err(match kind {
                    PendingInviteKind::Direct => "New invite not detected yet".to_string(),
                    PendingInviteKind::Group => "New group invite not detected yet".to_string(),
                });
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
}

#[tauri::command]
async fn runtime_invite(state: State<'_, RuntimeState>) -> Result<String, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut attempt = 0_u8;
    loop {
        let (agent_name, previous_revision, previous_error_revision) = {
            let mut manager = state.inner.lock().await;
            let runtime = active_runtime_mut(&mut manager)?;
            let previous_revision = runtime.latest_invite_revision;
            let previous_error_revision = runtime.latest_invite_error_revision;
            runtime.pending_invite_kind = Some(PendingInviteKind::Direct);
            if let Err(err) = send_line(runtime, "/invite").await {
                runtime.pending_invite_kind = None;
                return Err(err);
            }
            (
                runtime.name.clone(),
                previous_revision,
                previous_error_revision,
            )
        };
        match wait_for_invite_capture(
            state.inner(),
            &agent_name,
            PendingInviteKind::Direct,
            previous_revision,
            previous_error_revision,
        )
        .await
        {
            Ok(code) => return Ok(code),
            Err(error) if direct_invite_route_warming_up(&error) && attempt < 3 => {
                attempt = attempt.saturating_add(1);
                sleep(Duration::from_millis(1200)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[tauri::command]
async fn runtime_invite_group(
    state: State<'_, RuntimeState>,
    group_name: String,
) -> Result<String, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision, previous_error_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let group_name = group_name.trim();
        if group_name.is_empty() {
            return Err("Group name is required".to_string());
        }
        let previous_revision = runtime.latest_group_invite_revision;
        let previous_error_revision = runtime.latest_group_invite_error_revision;
        runtime.pending_invite_kind = Some(PendingInviteKind::Group);
        let command = UiBridgeCommand::CreateGroup {
            anonymous: runtime.mode.eq_ignore_ascii_case("ghost"),
            name: group_name.to_string(),
        };
        if let Err(err) = send_ui_bridge_command(runtime, command).await {
            runtime.pending_invite_kind = None;
            return Err(err);
        }
        (
            runtime.name.clone(),
            previous_revision,
            previous_error_revision,
        )
    };
    wait_for_invite_capture(
        state.inner(),
        &agent_name,
        PendingInviteKind::Group,
        previous_revision,
        previous_error_revision,
    )
    .await
}

#[tauri::command]
async fn runtime_regenerate_group_invite(
    state: State<'_, RuntimeState>,
    group_id: String,
) -> Result<String, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision, previous_error_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let group_id = group_id.trim();
        if group_id.is_empty() {
            return Err("Group id is required".to_string());
        }
        let group = runtime
            .mailbox_groups
            .iter()
            .find(|group| group.group_id == group_id)
            .cloned()
            .ok_or_else(|| format!("Unknown mailbox group '{}'", group_id))?;
        let previous_revision = runtime.latest_group_invite_revision;
        let previous_error_revision = runtime.latest_group_invite_error_revision;
        runtime.pending_invite_kind = Some(PendingInviteKind::Group);
        let command = if group.anonymous_group {
            let owner_special_id = group.owner_special_id.clone().ok_or_else(|| {
                format!(
                    "Anonymous mailbox group '{}' is missing owner handle",
                    group_id
                )
            })?;
            UiBridgeCommand::GenerateAnonymousGroupInvite { owner_special_id }
        } else {
            UiBridgeCommand::GenerateGroupInvite {
                group_id: group.group_id,
            }
        };
        if let Err(err) = send_ui_bridge_command(runtime, command).await {
            runtime.pending_invite_kind = None;
            return Err(err);
        }
        (
            runtime.name.clone(),
            previous_revision,
            previous_error_revision,
        )
    };
    wait_for_invite_capture(
        state.inner(),
        &agent_name,
        PendingInviteKind::Group,
        previous_revision,
        previous_error_revision,
    )
    .await
}

#[tauri::command]
async fn runtime_accept_group_handshake_offer(
    state: State<'_, RuntimeState>,
    sender_member_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let sender_member_id = sender_member_id.trim();
    if sender_member_id.is_empty() {
        return Err("Sender member id is required".to_string());
    }
    runtime
        .group_events
        .retain(|event| event.sender_member_id.as_deref() != Some(sender_member_id));
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Accept {
            selector: sender_member_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_reject_group_handshake_offer(
    state: State<'_, RuntimeState>,
    sender_member_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let sender_member_id = sender_member_id.trim();
    if sender_member_id.is_empty() {
        return Err("Sender member id is required".to_string());
    }
    runtime
        .group_events
        .retain(|event| event.sender_member_id.as_deref() != Some(sender_member_id));
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Reject {
            selector: sender_member_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_block_group_handshake_offer(
    state: State<'_, RuntimeState>,
    sender_member_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let sender_member_id = sender_member_id.trim();
    if sender_member_id.is_empty() {
        return Err("Sender member id is required".to_string());
    }
    runtime
        .group_events
        .retain(|event| event.sender_member_id.as_deref() != Some(sender_member_id));
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Block {
            selector: sender_member_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_accept_group_file_offer(
    state: State<'_, RuntimeState>,
    manifest_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let manifest_id = manifest_id.trim();
    if manifest_id.is_empty() {
        return Err("Manifest id is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Accept {
            selector: manifest_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_reject_group_file_offer(
    state: State<'_, RuntimeState>,
    manifest_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let manifest_id = manifest_id.trim();
    if manifest_id.is_empty() {
        return Err("Manifest id is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Reject {
            selector: manifest_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_set_selected_peer(
    state: State<'_, RuntimeState>,
    peer: String,
) -> Result<(), String> {
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let peer = normalize_peer_selector(&peer);
    if peer.is_empty() {
        return Err("Peer is required".to_string());
    }
    runtime.selected_peer = Some(peer);
    Ok(())
}

#[tauri::command]
async fn runtime_send_message(
    state: State<'_, RuntimeState>,
    message: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let peer = runtime
        .selected_peer
        .clone()
        .ok_or_else(|| "Select a peer first".to_string())?;
    let msg = message.trim();
    if msg.is_empty() {
        return Err("Message is empty".to_string());
    }
    let selector = normalize_peer_selector(&peer);
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::SendTo {
            selector,
            message: msg.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_send_group_message(
    state: State<'_, RuntimeState>,
    group_id: String,
    message: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let group_id = group_id.trim();
    let message = message.trim();
    if group_id.is_empty() || message.is_empty() {
        return Err("Group id and message are required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::SendTo {
            selector: group_id.to_string(),
            message: message.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_send_console_input(
    state: State<'_, RuntimeState>,
    message: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let message = message.trim();
    if message.is_empty() {
        return Err("Message is empty".to_string());
    }
    send_line_silent(runtime, message).await
}

#[tauri::command]
async fn runtime_sendto(
    state: State<'_, RuntimeState>,
    req: PeerMessageRequest,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let peer = req.peer.trim();
    let msg = req.message.trim();
    if peer.is_empty() || msg.is_empty() {
        return Err("Peer and message are required".to_string());
    }
    let selector = normalize_peer_selector(peer);
    runtime.selected_peer = Some(selector.clone());
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::SendTo {
            selector,
            message: msg.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_connect_invite(
    state: State<'_, RuntimeState>,
    code: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let code = code.trim();
    if code.is_empty() {
        return Err("Invite code is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::ConnectInvite {
            code: code.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_connect_did(state: State<'_, RuntimeState>, did: String) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let did = did.trim();
    if did.is_empty() {
        return Err("Peer DID is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::ConnectDid {
            did: did.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_disconnect_peer(
    state: State<'_, RuntimeState>,
    did: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let did = did.trim();
    if did.is_empty() {
        return Err("Peer did is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::DisconnectPeer {
            did: did.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_forget_peer_history(
    state: State<'_, RuntimeState>,
    did: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let did = did.trim();
    if did.is_empty() {
        return Err("Peer did is required".to_string());
    }

    runtime.direct_events.retain(|event| {
        event
            .peer_canonical_did
            .as_deref()
            .unwrap_or(&event.peer_did)
            != did
    });
    runtime
        .transfer_events
        .retain(|event| canonical_transfer_peer_did(event) != Some(did));
    runtime
        .peer_events
        .retain(|event| event.canonical_did.as_deref().unwrap_or(&event.did) != did);
    runtime.pending_approvals.retain(|pending| pending != did);
    runtime
        .ghost_handoffs
        .retain(|_, handoff| handoff.peer_did != did);
    if runtime.selected_peer.as_deref() == Some(did) {
        runtime.selected_peer = None;
    }
    Ok(())
}

#[tauri::command]
async fn runtime_send_group_handshake_invite(
    state: State<'_, RuntimeState>,
    group_id: String,
    member_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let group_id = group_id.trim();
    let member_id = member_id.trim();
    if group_id.is_empty() || member_id.is_empty() {
        return Err("Group id and member id are required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::SendGroupHandshakeInvite {
            group_id: group_id.to_string(),
            member_id: member_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_set_handshake_request_block(
    state: State<'_, RuntimeState>,
    member_id: String,
    blocked: bool,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let member_id = member_id.trim();
    if member_id.is_empty() {
        return Err("Member id is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::SetHandshakeRequestBlock {
            member_id: member_id.to_string(),
            blocked,
        },
    )
    .await
}

#[tauri::command]
async fn runtime_set_incoming_connect_block(
    state: State<'_, RuntimeState>,
    did: String,
    blocked: bool,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let did = did.trim();
    if did.is_empty() {
        return Err("Peer DID is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::SetIncomingConnectBlock {
            did: did.to_string(),
            blocked,
        },
    )
    .await
}

#[tauri::command]
async fn runtime_set_incoming_connect_block_all(
    state: State<'_, RuntimeState>,
    blocked: bool,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let command = if blocked {
        "/block_inv all"
    } else {
        "/unlock_inv all"
    };
    send_line(runtime, command).await?;
    runtime.incoming_connect_policy.block_all = blocked;
    runtime.incoming_connect_policy_known = true;
    Ok(())
}

#[tauri::command]
async fn runtime_set_handshake_request_block_all(
    state: State<'_, RuntimeState>,
    blocked: bool,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let command = if blocked {
        "/block_all_r"
    } else {
        "/unblock_all_r"
    };
    send_line(runtime, command).await
}

#[tauri::command]
async fn runtime_kick_group_member(
    state: State<'_, RuntimeState>,
    member_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let member_id = member_id.trim();
    if member_id.is_empty() {
        return Err("Member id is required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::KickGroupMember {
            member_id: member_id.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_set_group_join_lock(
    state: State<'_, RuntimeState>,
    group_id: String,
    locked: bool,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let group_id = group_id.trim();
        if group_id.is_empty() {
            return Err("Group id is required".to_string());
        }
        let previous_revision = runtime.mailbox_group_revision;
        send_ui_bridge_command(
            runtime,
            UiBridgeCommand::SetGroupJoinLock {
                group_id: group_id.to_string(),
                locked,
            },
        )
        .await?;
        (runtime.name.clone(), previous_revision)
    };
    let _ = wait_for_group_refresh(state.inner(), &agent_name, previous_revision).await?;
    Ok(())
}

#[tauri::command]
async fn runtime_leave_group(
    state: State<'_, RuntimeState>,
    group_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let group_id = group_id.trim();
        if group_id.is_empty() {
            return Err("Group id is required".to_string());
        }
        let previous_revision = runtime.mailbox_group_revision;
        send_ui_bridge_command(
            runtime,
            UiBridgeCommand::LeaveGroup {
                group_id: group_id.to_string(),
            },
        )
        .await?;
        (runtime.name.clone(), previous_revision)
    };
    let _ = wait_for_group_refresh(state.inner(), &agent_name, previous_revision).await?;
    Ok(())
}

#[tauri::command]
async fn runtime_disband_group(
    state: State<'_, RuntimeState>,
    group_id: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let group_id = group_id.trim();
        if group_id.is_empty() {
            return Err("Group id is required".to_string());
        }
        let previous_revision = runtime.mailbox_group_revision;
        send_ui_bridge_command(
            runtime,
            UiBridgeCommand::DisbandGroup {
                group_id: group_id.to_string(),
            },
        )
        .await?;
        (runtime.name.clone(), previous_revision)
    };
    let _ = wait_for_group_refresh(state.inner(), &agent_name, previous_revision).await?;
    Ok(())
}

#[tauri::command]
async fn runtime_transfer(
    state: State<'_, RuntimeState>,
    req: TransferRequest,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let peer = normalize_peer_selector(&req.peer);
    let path = req.path.trim();
    if peer.is_empty() || path.is_empty() {
        return Err("Peer and file path are required".to_string());
    }
    // Use numbered selector when a DID is provided, so transfer works with
    // runtimes that expect <number|name> for /transfer.
    let selector = if peer.starts_with("did:nxf:") {
        let mut ordered = runtime.peers.values().cloned().collect::<Vec<_>>();
        ordered.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
        if let Some((idx, _)) = ordered.iter().enumerate().find(|(_, p)| p.did == peer) {
            (idx + 1).to_string()
        } else {
            peer.to_string()
        }
    } else {
        peer.to_string()
    };
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::TransferToPeer {
            selector,
            path: path.to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_transfer_group(
    state: State<'_, RuntimeState>,
    group_id: String,
    path: String,
) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    let group_id = group_id.trim();
    let path = path.trim();
    if group_id.is_empty() || path.is_empty() {
        return Err("Group id and file path are required".to_string());
    }
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::TransferToGroup {
            group_id: group_id.to_string(),
            path: path.to_string(),
        },
    )
    .await
}

#[tauri::command]
fn pick_transfer_path(window: tauri::Window) -> Option<TransferPickerSelection> {
    prepare_window_for_native_dialog(&window);
    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = std::sync::mpsc::channel();
        if window
            .run_on_main_thread(move || {
                let _ = tx.send(pick_transfer_path_macos_native());
            })
            .is_err()
        {
            clear_window_attention(&window);
            return None;
        }
        let picked = rx.recv().ok().flatten();
        clear_window_attention(&window);
        return picked;
    }

    #[cfg(not(target_os = "macos"))]
    {
        let picked = build_transfer_file_dialog(&window)
            .pick_file()
            .or_else(|| build_transfer_file_dialog(&window).pick_folder());
        clear_window_attention(&window);
        picked.and_then(transfer_picker_selection_from_path)
    }
}

#[cfg(target_os = "macos")]
fn pick_transfer_path_macos_native() -> Option<TransferPickerSelection> {
    let mtm = MainThreadMarker::new()?;
    let app = NSApplication::sharedApplication(mtm);
    app.activate();
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);

    let panel = NSOpenPanel::openPanel(mtm);
    panel.setCanChooseFiles(true);
    panel.setCanChooseDirectories(true);
    panel.setAllowsMultipleSelection(false);
    panel.setCanCreateDirectories(false);

    let title = NSString::from_str("Select a file or folder to attach");
    panel.setTitle(Some(&title));

    let message = NSString::from_str("Choose any file or folder to send securely.");
    panel.setMessage(Some(&message));

    let prompt = NSString::from_str("Choose");
    panel.setPrompt(Some(&prompt));

    if panel.runModal() != NSModalResponseOK {
        return None;
    }

    let selected_url = panel.URL()?;
    let selected_path = selected_url.to_file_path()?;
    transfer_picker_selection_from_path(selected_path)
}

fn transfer_picker_selection_from_path(path: PathBuf) -> Option<TransferPickerSelection> {
    let normalized = normalize_selected_path(path)?;
    let metadata = fs::metadata(&normalized).ok()?;
    Some(TransferPickerSelection {
        path: normalized.display().to_string(),
        is_dir: metadata.is_dir(),
    })
}

fn normalize_selected_path(path: PathBuf) -> Option<PathBuf> {
    let raw = path.to_string_lossy().trim().to_string();
    if raw.is_empty() {
        return None;
    }
    let trimmed = raw
        .trim_end_matches(std::path::MAIN_SEPARATOR)
        .trim_end_matches('/')
        .trim_end_matches('\\')
        .to_string();
    if trimmed.is_empty() {
        return Some(path);
    }
    Some(PathBuf::from(trimmed))
}

fn prepare_window_for_native_dialog(window: &tauri::Window) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        let _ = window.request_user_attention(Some(tauri::UserAttentionType::Critical));
    }
}

fn clear_window_attention(_window: &tauri::Window) {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        let _ = _window.request_user_attention(None);
    }
}

#[cfg(not(target_os = "macos"))]
fn build_transfer_file_dialog(window: &tauri::Window) -> rfd::FileDialog {
    let dialog = rfd::FileDialog::new().set_title("Select a file or folder to attach");
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let dialog = dialog.set_parent(window);
    dialog
}

#[tauri::command]
fn pick_transfer_file() -> Option<String> {
    rfd::FileDialog::new()
        .pick_file()
        .map(|path| path.display().to_string())
}

#[tauri::command]
fn pick_transfer_folder() -> Option<String> {
    rfd::FileDialog::new()
        .pick_folder()
        .map(|path| path.display().to_string())
}

#[tauri::command]
async fn runtime_accept(state: State<'_, RuntimeState>, peer: String) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Accept {
            selector: peer.trim().to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_reject(state: State<'_, RuntimeState>, peer: String) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::Reject {
            selector: peer.trim().to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_accept_always(state: State<'_, RuntimeState>, peer: String) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::AcceptAlways {
            selector: peer.trim().to_string(),
        },
    )
    .await
}

#[tauri::command]
async fn runtime_accept_ask(state: State<'_, RuntimeState>, peer: String) -> Result<(), String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let mut manager = state.inner.lock().await;
    let runtime = active_runtime_mut(&mut manager)?;
    send_ui_bridge_command(
        runtime,
        UiBridgeCommand::AcceptAsk {
            selector: peer.trim().to_string(),
        },
    )
    .await
}

#[tauri::command]
fn get_workspace_root() -> String {
    workspace_root().to_string_lossy().to_string()
}

#[tauri::command]
async fn set_receive_dir(state: State<'_, RuntimeState>, path: String) -> Result<String, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let trimmed = path.trim();
        let previous_revision = runtime.receive_dir_revision;
        let path = if trimmed.is_empty() || trimmed == "default" || trimmed == "reset" {
            None
        } else {
            Some(trimmed.to_string())
        };
        send_ui_bridge_command(runtime, UiBridgeCommand::SetReceiveDir { path }).await?;
        (runtime.name.clone(), previous_revision)
    };
    wait_for_receive_dir_refresh(state.inner(), &agent_name, previous_revision).await
}

#[tauri::command]
async fn get_receive_dir(state: State<'_, RuntimeState>) -> Result<String, String> {
    let gate = active_runtime_command_gate(state.inner()).await?;
    let _command_guard = gate.lock().await;
    let (agent_name, previous_revision) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let previous_revision = runtime.receive_dir_revision;
        send_line(runtime, "/get_receive_dir").await?;
        (runtime.name.clone(), previous_revision)
    };
    wait_for_receive_dir_refresh(state.inner(), &agent_name, previous_revision).await
}

#[tauri::command]
async fn runtime_export_handoff(
    app: tauri::AppHandle,
    state: State<'_, RuntimeState>,
    handoff_id: String,
) -> Result<(), String> {
    let trimmed = handoff_id.trim().to_string();
    if trimmed.is_empty() {
        return Err("Handoff id is required".to_string());
    }

    let (agent_name, receive_root, handoff) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let receive_root = runtime
            .receive_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_receive_root);
        let handoff = runtime
            .ghost_handoffs
            .remove(&trimmed)
            .ok_or_else(|| format!("Ghost handoff '{}' not found", trimmed))?;
        (runtime.name.clone(), receive_root, handoff)
    };

    match export_handoff_to_receive_dir(&handoff, &receive_root) {
        Ok(exported_path) => {
            let contact_did = contact_did_from_canonical_did(&handoff.peer_did);
            let transfer_event = TransferRuntimeEvent {
                agent: agent_name.clone(),
                event: "incoming_exported".to_string(),
                direction: "in".to_string(),
                peer_did: contact_did
                    .clone()
                    .or_else(|| Some(handoff.peer_did.clone())),
                peer_contact_did: contact_did,
                peer_canonical_did: Some(handoff.peer_did),
                peer_name: Some(handoff.peer_name),
                session_id: None,
                filename: Some(handoff.filename),
                reason: Some(exported_path.display().to_string()),
                handoff_id: Some(handoff.handoff_id),
                group_id: None,
                group_name: None,
                transferred_chunks: None,
                total_chunks: None,
                transferred_bytes: None,
                total_bytes: None,
                percent: None,
                ts_ms: Utc::now().timestamp_millis(),
            };
            {
                let mut manager = state.inner.lock().await;
                if let Some(runtime) = manager.runtimes.get_mut(&agent_name) {
                    push_transfer_event(runtime, transfer_event.clone());
                }
            }
            let _ = app.emit("qypha://transfer-event", transfer_event);
            Ok(())
        }
        Err(err) => {
            let mut manager = state.inner.lock().await;
            if let Some(runtime) = manager.runtimes.get_mut(&agent_name) {
                runtime
                    .ghost_handoffs
                    .insert(handoff.handoff_id.clone(), handoff);
            }
            Err(err)
        }
    }
}

#[tauri::command]
async fn runtime_discard_handoff(
    app: tauri::AppHandle,
    state: State<'_, RuntimeState>,
    handoff_id: String,
) -> Result<(), String> {
    let trimmed = handoff_id.trim().to_string();
    if trimmed.is_empty() {
        return Err("Handoff id is required".to_string());
    }

    let (agent_name, handoff) = {
        let mut manager = state.inner.lock().await;
        let runtime = active_runtime_mut(&mut manager)?;
        let handoff = runtime
            .ghost_handoffs
            .remove(&trimmed)
            .ok_or_else(|| format!("Ghost handoff '{}' not found", trimmed))?;
        (runtime.name.clone(), handoff)
    };

    match secure_wipe_dir_local(&handoff.staged_path) {
        Ok(()) => {
            let contact_did = contact_did_from_canonical_did(&handoff.peer_did);
            let transfer_event = TransferRuntimeEvent {
                agent: agent_name.clone(),
                event: "incoming_discarded".to_string(),
                direction: "in".to_string(),
                peer_did: contact_did
                    .clone()
                    .or_else(|| Some(handoff.peer_did.clone())),
                peer_contact_did: contact_did,
                peer_canonical_did: Some(handoff.peer_did),
                peer_name: Some(handoff.peer_name),
                session_id: None,
                filename: Some(handoff.filename),
                reason: Some("ghost_secure_handoff_discarded".to_string()),
                handoff_id: Some(handoff.handoff_id),
                group_id: None,
                group_name: None,
                transferred_chunks: None,
                total_chunks: None,
                transferred_bytes: None,
                total_bytes: None,
                percent: None,
                ts_ms: Utc::now().timestamp_millis(),
            };
            {
                let mut manager = state.inner.lock().await;
                if let Some(runtime) = manager.runtimes.get_mut(&agent_name) {
                    push_transfer_event(runtime, transfer_event.clone());
                }
            }
            let _ = app.emit("qypha://transfer-event", transfer_event);
            Ok(())
        }
        Err(err) => {
            let mut manager = state.inner.lock().await;
            if let Some(runtime) = manager.runtimes.get_mut(&agent_name) {
                runtime
                    .ghost_handoffs
                    .insert(handoff.handoff_id.clone(), handoff);
            }
            Err(err)
        }
    }
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(3)
        .map(PathBuf::from)
        .unwrap_or(manifest_dir)
}

fn default_receive_root() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("Desktop")
        .join("received")
}

fn export_handoff_to_receive_dir(
    handoff: &GhostHandoff,
    receive_root: &Path,
) -> Result<PathBuf, String> {
    if !handoff.staged_path.exists() {
        return Err(format!(
            "Secure handoff staging path is missing: {}",
            handoff.staged_path.display()
        ));
    }

    fs::create_dir_all(receive_root).map_err(|e| {
        format!(
            "Failed to prepare receive directory '{}': {}",
            receive_root.display(),
            e
        )
    })?;

    let mut entries = fs::read_dir(&handoff.staged_path)
        .map_err(|e| format!("Failed to read secure handoff staging dir: {}", e))?
        .flatten()
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    if entries.is_empty() {
        return Err("Secure handoff staging dir is empty".to_string());
    }

    if entries.len() == 1 {
        let entry = entries.remove(0);
        let destination = receive_root.join(entry.file_name());
        move_or_copy_path(&entry.path(), &destination)?;
        secure_wipe_dir_local(&handoff.staged_path)?;
        return Ok(destination);
    }

    let container_name = handoff_container_name(&handoff.filename, &handoff.handoff_id);
    let container_dir = receive_root.join(container_name);
    if container_dir.exists() {
        return Err(format!(
            "Export target already exists: {}",
            container_dir.display()
        ));
    }
    fs::create_dir_all(&container_dir).map_err(|e| {
        format!(
            "Failed to create export container '{}': {}",
            container_dir.display(),
            e
        )
    })?;

    for entry in entries {
        let destination = container_dir.join(entry.file_name());
        move_or_copy_path(&entry.path(), &destination)?;
    }

    secure_wipe_dir_local(&handoff.staged_path)?;
    Ok(container_dir)
}

fn handoff_container_name(filename: &str, handoff_id: &str) -> String {
    let base = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(handoff_id);
    let sanitized = base
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if sanitized.is_empty() {
        handoff_id.to_string()
    } else {
        sanitized
    }
}

fn move_or_copy_path(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        return Err(format!(
            "Export target already exists: {}",
            destination.display()
        ));
    }
    let metadata = fs::symlink_metadata(source)
        .map_err(|e| format!("Failed to stat '{}' for export: {}", source.display(), e))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Refusing to export symlinked content from secure handoff: {}",
            source.display()
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to prepare export directory '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(_) if metadata.is_file() => {
            fs::copy(source, destination).map_err(|e| {
                format!(
                    "Failed to copy file '{}' -> '{}': {}",
                    source.display(),
                    destination.display(),
                    e
                )
            })?;
            secure_wipe_file_local(source)
        }
        Err(_) if metadata.is_dir() => {
            copy_dir_recursive(source, destination)?;
            secure_wipe_dir_local(source)
        }
        Err(e) => Err(format!(
            "Failed to move '{}' -> '{}': {}",
            source.display(),
            destination.display(),
            e
        )),
    }
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|e| {
        format!(
            "Failed to create directory '{}': {}",
            destination.display(),
            e
        )
    })?;
    for entry in fs::read_dir(source)
        .map_err(|e| format!("Failed to read directory '{}': {}", source.display(), e))?
    {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        let next = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed to stat '{}' during export: {}", path.display(), e))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Refusing to export symlinked content from secure handoff: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            copy_dir_recursive(&path, &next)?;
        } else {
            fs::copy(&path, &next).map_err(|e| {
                format!(
                    "Failed to copy file '{}' -> '{}': {}",
                    path.display(),
                    next.display(),
                    e
                )
            })?;
        }
    }
    Ok(())
}

fn secure_wipe_dir_local(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| {
        format!(
            "Failed to read directory '{}' for wipe: {}",
            dir.display(),
            e
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to enumerate wipe target: {}", e))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed to stat '{}' for wipe: {}", path.display(), e))?;
        if metadata.file_type().is_symlink() {
            fs::remove_file(&path).map_err(|e| {
                format!(
                    "Failed to remove symlink '{}' during wipe: {}",
                    path.display(),
                    e
                )
            })?;
        } else if metadata.is_dir() {
            secure_wipe_dir_local(&path)?;
        } else {
            secure_wipe_file_local(&path)?;
        }
    }
    fs::remove_dir_all(dir)
        .map_err(|e| format!("Failed to remove directory '{}': {}", dir.display(), e))?;
    Ok(())
}

fn secure_wipe_file_local(path: &Path) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};

    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("Failed to stat '{}': {}", path.display(), e))?;
    if metadata.file_type().is_symlink() {
        fs::remove_file(path)
            .map_err(|e| format!("Failed to remove symlink '{}': {}", path.display(), e))?;
        return Ok(());
    }

    let size = metadata.len() as usize;
    if size > 0 {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("Failed to open '{}' for wipe: {}", path.display(), e))?;
        let mut remaining = size;
        let mut buf = vec![0u8; 1024 * 1024];
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            for byte in &mut buf[..chunk] {
                *byte = rand::random::<u8>();
            }
            file.write_all(&buf[..chunk])
                .map_err(|e| format!("Failed to overwrite '{}': {}", path.display(), e))?;
            remaining -= chunk;
        }
        file.sync_all()
            .map_err(|e| format!("Failed to flush '{}' during wipe: {}", path.display(), e))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to rewind '{}' during wipe: {}", path.display(), e))?;
        file.set_len(0)
            .map_err(|e| format!("Failed to truncate '{}' during wipe: {}", path.display(), e))?;
        file.sync_all().map_err(|e| {
            format!(
                "Failed to flush '{}' during truncate: {}",
                path.display(),
                e
            )
        })?;
    }

    fs::remove_file(path)
        .map_err(|e| format!("Failed to remove '{}' after wipe: {}", path.display(), e))?;
    Ok(())
}

fn sanitized_agent_name(agent_name: &str) -> String {
    let trimmed = agent_name.trim().to_lowercase();
    if trimmed.is_empty() {
        "agent".to_string()
    } else {
        trimmed.replace(' ', "_")
    }
}

fn derived_agent_config_path(root: &Path, agent_name: &str) -> PathBuf {
    root.join("agent-configs")
        .join(format!("qypha_{}.toml", sanitized_agent_name(agent_name)))
}

fn active_agent_selection_path(root: &Path) -> PathBuf {
    root.join("agent-configs").join("qypha_active_agent.txt")
}

fn embedded_runtime_root_path(root: &Path) -> PathBuf {
    root.join("agent-configs").join("qypha-runtime")
}

fn legacy_embedded_runtime_root_path(root: &Path) -> PathBuf {
    root.join("agent-configs").join("embedded-runtime")
}

fn embedded_runtime_agent_path(root: &Path, agent_name: &str) -> PathBuf {
    embedded_runtime_root_path(root).join(sanitized_agent_name(agent_name))
}

fn legacy_embedded_runtime_agent_path(root: &Path, agent_name: &str) -> PathBuf {
    legacy_embedded_runtime_root_path(root).join(sanitized_agent_name(agent_name))
}

fn agent_skills_root_path(root: &Path, agent_name: &str) -> PathBuf {
    embedded_runtime_agent_path(root, agent_name).join("skills")
}

fn agent_skill_dir_path(root: &Path, agent_name: &str, skill_id: &str) -> PathBuf {
    agent_skills_root_path(root, agent_name).join(sanitized_skill_identifier(skill_id))
}

fn agent_skill_markdown_path(root: &Path, agent_name: &str, skill_id: &str) -> PathBuf {
    agent_skill_dir_path(root, agent_name, skill_id).join("SKILL.md")
}

fn agent_metadata_path(root: &Path, agent_name: &str) -> PathBuf {
    root.join("agent-configs").join(format!(
        "qypha_{}.desktop-profile.json",
        sanitized_agent_name(agent_name)
    ))
}

fn load_persisted_active_agent(root: &Path) -> Option<String> {
    let content = fs::read_to_string(active_agent_selection_path(root)).ok()?;
    let name = content.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn save_persisted_active_agent(root: &Path, agent_name: &str) -> Result<(), std::io::Error> {
    let path = active_agent_selection_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, agent_name.trim().as_bytes())
}

fn clear_persisted_active_agent(root: &Path) -> Result<(), std::io::Error> {
    let path = active_agent_selection_path(root);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn apply_preferred_active_agent(
    root: &Path,
    manager: &mut RuntimeManager,
    profiles: &[AgentProfile],
) {
    let preferred = manager
        .active_agent
        .clone()
        .filter(|name| profiles.iter().any(|profile| profile.name == *name))
        .or_else(|| {
            load_persisted_active_agent(root)
                .filter(|name| profiles.iter().any(|profile| profile.name == *name))
        })
        .or_else(|| profiles.first().map(|profile| profile.name.clone()));

    if let Some(target) = preferred {
        if !manager.runtimes.contains_key(&target) {
            if let Some(profile) = profiles.iter().find(|profile| profile.name == target) {
                manager
                    .runtimes
                    .insert(target.clone(), runtime_from_profile(profile));
            }
        }
        manager.active_agent = Some(target.clone());
        let _ = save_persisted_active_agent(root, &target);
    } else {
        manager.active_agent = None;
        let _ = clear_persisted_active_agent(root);
    }
}

fn normalize_agent_type(value: &str) -> Option<DesktopAgentType> {
    match value.trim().to_lowercase().as_str() {
        "" | "human" => Some(DesktopAgentType::Human),
        "ai" => Some(DesktopAgentType::Ai),
        _ => None,
    }
}

fn normalize_ai_role_value(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "" | "general" => "general".to_string(),
        other => other.to_string(),
    }
}

fn normalize_ai_access_mode_value(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "" | "full" | "full_access" => "full_access".to_string(),
        other => other.to_string(),
    }
}

fn normalize_agent_mode(mode: &str) -> Option<String> {
    match mode.trim().to_lowercase().as_str() {
        "ghost" => Some("ghost".to_string()),
        "safe" | "" => Some("safe".to_string()),
        _ => None,
    }
}

fn normalize_agent_transport(transport: &str) -> Option<String> {
    match transport.trim().to_lowercase().as_str() {
        "tcp" | "" => Some("tcp".to_string()),
        "tor" => Some("tor".to_string()),
        "internet" => Some("internet".to_string()),
        _ => None,
    }
}

fn display_transport_label(transport: &str) -> &'static str {
    match transport.trim().to_lowercase().as_str() {
        "tcp" | "lan" => "LAN",
        "tor" => "Tor",
        "internet" => "Internet",
        _ => "state only",
    }
}

fn provider_label(provider: &str) -> &'static str {
    match provider.trim().to_lowercase().as_str() {
        "ollama" => "Ollama",
        "openai" => "OpenAI",
        "claude" | "anthropic" => "Claude",
        "gemini" | "google" => "Gemini",
        _ => "Provider",
    }
}

fn normalize_desktop_ai_provider(provider: &str) -> Option<&'static str> {
    match provider.trim().to_lowercase().as_str() {
        "openai" => Some("openai"),
        "claude" | "anthropic" => Some("claude"),
        "gemini" | "google" => Some("gemini"),
        _ => None,
    }
}

fn provider_secret_env_hint(provider: &str) -> Option<&'static str> {
    match normalize_desktop_ai_provider(provider) {
        Some("openai") => Some("OPENAI_API_KEY"),
        Some("claude") => Some("ANTHROPIC_API_KEY"),
        Some("gemini") => Some("GEMINI_API_KEY"),
        _ => None,
    }
}

fn ai_provider_secret_entry(provider: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("qypha-desktop.ai-provider", provider)
        .map_err(|error| format!("Failed to prepare secure storage entry: {error}"))
}

fn read_ai_provider_secret_status(provider: &str) -> AiProviderSecretStatus {
    let configured = ai_provider_secret_entry(provider)
        .and_then(|entry| match entry.get_password() {
            Ok(secret) => Ok(!secret.trim().is_empty()),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(format!("Failed to inspect stored credential: {error}")),
        })
        .unwrap_or(false);

    AiProviderSecretStatus {
        provider: provider.to_string(),
        provider_label: provider_label(provider).to_string(),
        env_var_hint: provider_secret_env_hint(provider).map(|value| value.to_string()),
        configured,
        storage_label: "system secure storage".to_string(),
    }
}

fn load_agent_desktop_metadata(path: &Path) -> Option<AgentDesktopMetadata> {
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str::<AgentDesktopMetadata>(&content)
        .ok()
        .map(AgentDesktopMetadata::normalized)
}

fn save_agent_desktop_metadata(
    root: &Path,
    agent_name: &str,
    metadata: &AgentDesktopMetadata,
) -> Result<(), std::io::Error> {
    let path = agent_metadata_path(root, agent_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(metadata)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    fs::write(path, json)
}

fn normalized_ollama_host() -> String {
    let raw = std::env::var("OLLAMA_HOST")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
    if raw.starts_with("http://") || raw.starts_with("https://") {
        raw
    } else {
        format!("http://{raw}")
    }
}

fn configured_ollama_cloud_models() -> Vec<String> {
    let mut models = Vec::new();
    for key in ["QYPHA_OLLAMA_CLOUD_MODELS", "OLLAMA_CLOUD_MODELS"] {
        if let Ok(value) = std::env::var(key) {
            models.extend(
                value
                    .split(',')
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty()),
            );
        }
    }
    models.sort();
    models.dedup();
    models
}

fn ai_agent_thread_path(root: &Path, ai_agent: &str, requester_agent: Option<&str>) -> PathBuf {
    let requester_segment = requester_agent
        .map(sanitized_agent_name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "self".to_string());
    root.join("agent-configs").join(format!(
        "qypha_{}.thread_{}.ai-chat.json",
        sanitized_agent_name(ai_agent),
        requester_segment
    ))
}

fn list_ai_agent_thread_paths(root: &Path, ai_agent: &str) -> Vec<PathBuf> {
    let prefix = format!("qypha_{}.thread_", sanitized_agent_name(ai_agent));
    let mut paths = Vec::new();
    let config_root = root.join("agent-configs");
    if let Ok(entries) = fs::read_dir(&config_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.starts_with(&prefix) && name.ends_with(".ai-chat.json") {
                paths.push(path);
            }
        }
    }
    paths
}

fn persisted_active_agent_matches(root: &Path, agent_name: &str) -> bool {
    let Some(active) = load_persisted_active_agent(root) else {
        return false;
    };
    sanitized_agent_name(&active) == sanitized_agent_name(agent_name)
}

fn secure_wipe_ai_agent_workspace_state(root: &Path, agent_name: &str) {
    let metadata_path = agent_metadata_path(root, agent_name);
    if metadata_path.exists() {
        let _ = secure_wipe_file_local(&metadata_path);
    }
    for thread_path in list_ai_agent_thread_paths(root, agent_name) {
        let _ = secure_wipe_file_local(&thread_path);
    }
    let embedded_agent_dir = embedded_runtime_agent_path(root, agent_name);
    if embedded_agent_dir.exists() {
        let _ = secure_wipe_dir_local(&embedded_agent_dir);
    }
    let legacy_embedded_agent_dir = legacy_embedded_runtime_agent_path(root, agent_name);
    if legacy_embedded_agent_dir.exists() {
        let _ = secure_wipe_dir_local(&legacy_embedded_agent_dir);
    }
    let active_path = active_agent_selection_path(root);
    if active_path.exists() && persisted_active_agent_matches(root, agent_name) {
        let _ = secure_wipe_file_local(&active_path);
    }
}

fn secure_wipe_all_ai_workspace_state(root: &Path) {
    let config_root = root.join("agent-configs");
    if let Ok(entries) = fs::read_dir(&config_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name == "qypha_active_agent.txt"
                || (name.starts_with("qypha_")
                    && (name.ends_with(".desktop-profile.json") || name.ends_with(".ai-chat.json")))
            {
                let _ = secure_wipe_file_local(&path);
            }
        }
    }
    let embedded_root = embedded_runtime_root_path(root);
    if embedded_root.exists() {
        let _ = secure_wipe_dir_local(&embedded_root);
    }
    let legacy_embedded_root = legacy_embedded_runtime_root_path(root);
    if legacy_embedded_root.exists() {
        let _ = secure_wipe_dir_local(&legacy_embedded_root);
    }
}

fn ensure_private_dir_local(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Failed to create directory '{}': {}", path.display(), error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn sanitized_skill_identifier(value: &str) -> String {
    let trimmed = value.trim().to_lowercase();
    let filtered = trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if filtered.is_empty() {
        "skill".to_string()
    } else {
        filtered
    }
}

fn unique_skill_identifier(skills_root: &Path, requested_name: &str) -> String {
    let base = sanitized_skill_identifier(requested_name);
    if !skills_root.join(&base).exists() {
        return base;
    }
    for index in 2..10_000 {
        let candidate = format!("{base}-{index}");
        if !skills_root.join(&candidate).exists() {
            return candidate;
        }
    }
    format!("{}-{}", base, Utc::now().timestamp_millis())
}

fn yaml_double_quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn extract_frontmatter_value(frontmatter: &str, field: &str) -> Option<String> {
    frontmatter
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            let prefix = format!("{field}:");
            trimmed.strip_prefix(&prefix).map(str::trim)
        })
        .map(|value| value.trim_matches('"').trim_matches('\'').to_string())
        .filter(|value| !value.is_empty())
}

fn derive_skill_description(markdown: &str) -> String {
    let summary = markdown
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.trim_start_matches('#')
                .trim_start_matches('-')
                .trim()
                .to_string()
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "User-defined skill for this Qypha AI agent.".to_string());
    let max_chars = 180usize;
    if summary.chars().count() <= max_chars {
        summary
    } else {
        let truncated = summary.chars().take(max_chars - 1).collect::<String>();
        format!("{truncated}…")
    }
}

fn split_skill_frontmatter(raw: &str) -> (Option<String>, Option<String>, String) {
    let normalized = raw.replace("\r\n", "\n");
    if !normalized.starts_with("---\n") {
        return (None, None, raw.trim().to_string());
    }
    let remainder = &normalized[4..];
    let Some(end_offset) = remainder.find("\n---\n") else {
        return (None, None, raw.trim().to_string());
    };
    let frontmatter = &remainder[..end_offset];
    let body = remainder[end_offset + 5..].trim().to_string();
    let name = extract_frontmatter_value(frontmatter, "name");
    let description = extract_frontmatter_value(frontmatter, "description");
    (name, description, body)
}

fn build_agent_skill_markdown(skill_name: &str, markdown: &str) -> String {
    let (_, description_from_body, body) = split_skill_frontmatter(markdown);
    let description = description_from_body.unwrap_or_else(|| derive_skill_description(&body));
    format!(
        "---\nname: {}\ndescription: {}\n---\n\n{}\n",
        yaml_double_quoted(skill_name.trim()),
        yaml_double_quoted(&description),
        body.trim()
    )
}

fn file_modified_at_ms(path: &Path) -> i64 {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_else(|| Utc::now().timestamp_millis())
}

fn read_agent_skill_record(skill_dir: &Path) -> Result<Option<AgentSkillRecord>, String> {
    if !skill_dir.is_dir() {
        return Ok(None);
    }
    let skill_id = skill_dir
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_string())
        .ok_or_else(|| format!("Invalid skill directory '{}'", skill_dir.display()))?;
    let markdown_path = skill_dir.join("SKILL.md");
    if !markdown_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&markdown_path).map_err(|error| {
        format!(
            "Failed to read skill '{}': {}",
            markdown_path.display(),
            error
        )
    })?;
    let (frontmatter_name, _, markdown) = split_skill_frontmatter(&raw);
    Ok(Some(AgentSkillRecord {
        id: skill_id.clone(),
        name: frontmatter_name.unwrap_or(skill_id),
        file_path: markdown_path.display().to_string(),
        markdown,
        updated_at_ms: file_modified_at_ms(&markdown_path),
    }))
}

fn read_agent_skill_records(
    root: &Path,
    agent_name: &str,
) -> Result<Vec<AgentSkillRecord>, String> {
    let skills_root = agent_skills_root_path(root, agent_name);
    if !skills_root.exists() {
        return Ok(Vec::new());
    }
    let mut skills = Vec::new();
    for entry in fs::read_dir(&skills_root).map_err(|error| {
        format!(
            "Failed to read skills directory '{}': {}",
            skills_root.display(),
            error
        )
    })? {
        let entry = entry.map_err(|error| format!("Failed to read skill entry: {}", error))?;
        let path = entry.path();
        if let Some(skill) = read_agent_skill_record(&path)? {
            skills.push(skill);
        }
    }
    skills.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(skills)
}

fn build_ai_agent_system_prompt(metadata: &AgentDesktopMetadata) -> String {
    let provider = metadata.ai_provider.as_deref().unwrap_or("ollama");
    let model = metadata.ai_model.as_deref().unwrap_or("unset");
    format!(
        "You are Qypha embedded AI agent '{name}'. Role: {role}. Access mode: {access}. Provider: {provider}. Model: {model}. When the user asks who you are or which LLM is connected, identify yourself as a Qypha AI agent and clearly state Provider: {provider}, Model: {model}. Do not describe yourself as OpenClaw; that is only an internal runtime detail. Act as a reliable general-purpose agent. If a requested runtime capability is not wired yet in Qypha, say so briefly and continue helping with planning, reasoning, drafting, or analysis.",
        name = metadata.name,
        role = metadata.ai_role,
        access = metadata.ai_access_mode,
        provider = provider,
        model = model,
    )
}

fn load_ai_agent_thread_state(
    root: &Path,
    metadata: &AgentDesktopMetadata,
    requester_agent: Option<&str>,
) -> AiAgentThreadState {
    let path = ai_agent_thread_path(root, &metadata.name, requester_agent);
    let requester = requester_agent
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let default_state = AiAgentThreadState {
        ai_agent: metadata.name.clone(),
        requester_agent: requester.clone(),
        ai_provider: metadata.ai_provider.clone(),
        ai_model: metadata.ai_model.clone(),
        ai_role: metadata.ai_role.clone(),
        ai_access_mode: metadata.ai_access_mode.clone(),
        messages: Vec::new(),
    };
    let Ok(content) = fs::read_to_string(path) else {
        return default_state;
    };
    let Ok(parsed) = serde_json::from_str::<AiAgentThreadState>(&content) else {
        return default_state;
    };
    AiAgentThreadState {
        ai_agent: metadata.name.clone(),
        requester_agent: requester,
        ai_provider: metadata.ai_provider.clone(),
        ai_model: metadata.ai_model.clone(),
        ai_role: metadata.ai_role.clone(),
        ai_access_mode: metadata.ai_access_mode.clone(),
        messages: parsed.messages,
    }
}

fn save_ai_agent_thread_state(root: &Path, state: &AiAgentThreadState) -> Result<(), String> {
    let path = ai_agent_thread_path(root, &state.ai_agent, state.requester_agent.as_deref());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create AI thread directory: {error}"))?;
    }
    let json = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to serialize AI thread state: {error}"))?;
    fs::write(path, json).map_err(|error| format!("Failed to save AI thread state: {error}"))
}

fn parse_agent_profile_from_config(path: &Path, fallback_name: &str) -> Option<AgentProfile> {
    let content = fs::read_to_string(path).ok()?;
    let parsed: Option<AgentToml> = toml::from_str(&content).ok();
    let name = parsed
        .as_ref()
        .and_then(|p| p.agent.as_ref())
        .and_then(|a| a.name.clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| fallback_name.to_string());
    let logging_mode = parsed
        .as_ref()
        .and_then(|p| p.logging.as_ref())
        .and_then(|l| l.mode.clone());
    let security_mode = parsed
        .as_ref()
        .and_then(|p| p.security.as_ref())
        .and_then(|s| s.log_mode.clone());
    let raw_mode = logging_mode.or(security_mode);
    if raw_mode
        .as_deref()
        .is_some_and(|mode| normalize_agent_mode(mode).is_none())
    {
        let _ = secure_wipe_file_local(path);
        return None;
    }
    let mode = match raw_mode {
        Some(mode) => normalize_agent_mode(&mode)?,
        None => "safe".to_string(),
    };
    let transport = parsed
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .and_then(|n| n.transport_mode.clone())
        .map(|value| value.to_lowercase());
    if transport
        .as_deref()
        .is_some_and(|value| normalize_agent_transport(value).is_none())
    {
        let _ = secure_wipe_file_local(path);
        return None;
    }
    let transport = match transport {
        Some(value) => normalize_agent_transport(&value)?,
        None => "tcp".to_string(),
    };
    let port = parsed
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .and_then(|n| n.listen_port)
        .unwrap_or(9090);
    Some(AgentProfile {
        name,
        agent_type: DesktopAgentType::Human,
        ai_provider: None,
        ai_model: None,
        ai_role: None,
        ai_access_mode: None,
        mode,
        transport,
        listen_port: port,
        config_path: Some(path.display().to_string()),
    })
}

fn initialized_agent_names(root: &Path) -> Vec<String> {
    let agents_root = if root == workspace_root() {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        let Some(home) = home else {
            return Vec::new();
        };
        home.join(".qypha").join("agents")
    } else {
        root.join(".qypha").join("agents")
    };
    let Ok(entries) = fs::read_dir(&agents_root) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let identity = path.join("keys").join("agent_identity.json");
        if !identity.exists() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
            names.push(name.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn discover_agent_profiles(root: &Path) -> Vec<AgentProfile> {
    let mut profiles_by_name = HashMap::new();
    let config_root = root.join("agent-configs");
    if let Ok(entries) = fs::read_dir(&config_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(fname) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if !fname.starts_with("qypha_") || !fname.ends_with(".toml") {
                continue;
            }
            let fallback_name = fname
                .trim_start_matches("qypha_")
                .trim_end_matches(".toml")
                .to_string();
            if let Some(profile) = parse_agent_profile_from_config(&path, &fallback_name) {
                profiles_by_name
                    .entry(profile.name.clone())
                    .or_insert(profile);
            }
        }
    }

    for agent_name in initialized_agent_names(root) {
        profiles_by_name
            .entry(agent_name.clone())
            .or_insert_with(|| AgentProfile {
                name: agent_name.clone(),
                agent_type: DesktopAgentType::Human,
                ai_provider: None,
                ai_model: None,
                ai_role: None,
                ai_access_mode: None,
                mode: "unknown".to_string(),
                transport: "unknown".to_string(),
                listen_port: 0,
                config_path: Some(
                    derived_agent_config_path(root, &agent_name)
                        .display()
                        .to_string(),
                ),
            });
    }

    if let Ok(entries) = fs::read_dir(&config_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(fname) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if !fname.starts_with("qypha_") || !fname.ends_with(".desktop-profile.json") {
                continue;
            }
            let Some(metadata) = load_agent_desktop_metadata(&path) else {
                continue;
            };
            let profile = profiles_by_name
                .entry(metadata.name.clone())
                .or_insert_with(|| AgentProfile {
                    name: metadata.name.clone(),
                    agent_type: metadata.agent_type,
                    ai_provider: metadata.ai_provider.clone(),
                    ai_model: metadata.ai_model.clone(),
                    ai_role: Some(metadata.ai_role.clone()),
                    ai_access_mode: Some(metadata.ai_access_mode.clone()),
                    mode: "safe".to_string(),
                    transport: "unknown".to_string(),
                    listen_port: 0,
                    config_path: None,
                });
            profile.agent_type = metadata.agent_type;
            profile.ai_provider = metadata.ai_provider.clone();
            profile.ai_model = metadata.ai_model.clone();
            profile.ai_role = Some(metadata.ai_role.clone());
            profile.ai_access_mode = Some(metadata.ai_access_mode.clone());
            profile.mode = metadata.log_mode.clone();
            profile.transport = metadata.transport.clone();
            profile.listen_port = metadata.listen_port;
        }
    }

    let mut profiles = profiles_by_name.into_values().collect::<Vec<_>>();
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    profiles
}

fn runtime_from_profile(profile: &AgentProfile) -> AgentRuntime {
    AgentRuntime {
        name: profile.name.clone(),
        mode: profile.mode.clone(),
        transport: profile.transport.clone(),
        listen_port: profile.listen_port,
        config_path: profile.config_path.clone(),
        ..Default::default()
    }
}

fn build_app_snapshot(manager: &RuntimeManager, profiles: &[AgentProfile]) -> AppSnapshot {
    let mut name_set = BTreeSet::new();
    for p in profiles {
        name_set.insert(p.name.clone());
    }
    for name in manager.runtimes.keys() {
        name_set.insert(name.clone());
    }

    let mut profile_map: HashMap<String, AgentProfile> = HashMap::new();
    for p in profiles {
        profile_map.insert(p.name.clone(), p.clone());
    }

    let mut agents = Vec::new();
    for name in name_set {
        let runtime = manager.runtimes.get(&name);
        let profile = profile_map.get(&name);
        let mode = runtime
            .map(|r| r.mode.clone())
            .or_else(|| profile.map(|p| p.mode.clone()))
            .unwrap_or_else(|| "safe".to_string());
        let transport = runtime
            .map(|r| r.transport.clone())
            .or_else(|| profile.map(|p| p.transport.clone()))
            .unwrap_or_else(|| "tcp".to_string());
        let listen_port = runtime
            .map(|r| r.listen_port)
            .or_else(|| profile.map(|p| p.listen_port))
            .unwrap_or(9090);
        let config_path = runtime
            .and_then(|r| r.config_path.clone())
            .or_else(|| profile.and_then(|p| p.config_path.clone()));
        let config_present = config_path
            .as_deref()
            .map(Path::new)
            .map(Path::exists)
            .unwrap_or(false);
        let running = runtime.and_then(|r| r.child.as_ref()).is_some();
        let pid = runtime.and_then(|r| r.child.as_ref()).and_then(Child::id);
        let last_error = runtime.and_then(|r| r.last_error.clone());
        let incoming_connect_block_all = runtime
            .filter(|r| r.incoming_connect_policy_known)
            .map(|r| r.incoming_connect_policy.block_all)
            .unwrap_or(false);
        let incoming_connect_policy_known = runtime
            .map(|r| r.incoming_connect_policy_known)
            .unwrap_or(false);
        agents.push(AgentCard {
            name,
            agent_type: profile
                .map(|p| p.agent_type.as_str().to_string())
                .unwrap_or_else(|| "human".to_string()),
            ai_provider: profile.and_then(|p| p.ai_provider.clone()),
            ai_model: profile.and_then(|p| p.ai_model.clone()),
            ai_role: profile.and_then(|p| p.ai_role.clone()),
            ai_access_mode: profile.and_then(|p| p.ai_access_mode.clone()),
            mode,
            transport,
            listen_port,
            config_path,
            config_present,
            running,
            pid,
            last_error,
            incoming_connect_block_all,
            incoming_connect_policy_known,
        });
    }

    let runtime = manager
        .active_agent
        .as_ref()
        .and_then(|name| manager.runtimes.get(name))
        .map(|rt| snapshot_from_runtime(rt, 300));

    AppSnapshot {
        active_agent: manager.active_agent.clone(),
        agents,
        runtime,
    }
}

fn find_qypha_bin(root: &Path) -> Option<PathBuf> {
    // 1. Explicit env override
    if let Ok(explicit) = std::env::var("QYPHA_BIN") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }

    let binary_name = if cfg!(target_os = "windows") {
        "qypha.exe"
    } else {
        "qypha"
    };

    // 2. Bundled resource inside .app/Contents/Resources/ (macOS release)
    //    or next to the executable (Linux/Windows release)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // macOS: .app/Contents/MacOS/qypha → .app/Contents/Resources/qypha
            let macos_resource = exe_dir
                .parent() // Contents/
                .map(|p| p.join("Resources").join(binary_name));
            if let Some(ref p) = macos_resource {
                if p.exists() {
                    return Some(p.clone());
                }
            }
            // Linux/Windows: binary sits next to the executable
            let sibling = exe_dir.join(binary_name);
            if sibling.exists() {
                return Some(sibling);
            }
        }
    }

    // 3. Development: target/debug or target/release
    let debug_bin = root.join("target").join("debug").join(binary_name);
    if debug_bin.exists() && qypha_binary_is_fresh(root, &debug_bin) {
        return Some(debug_bin);
    }
    let release_bin = root.join("target").join("release").join(binary_name);
    if release_bin.exists() && qypha_binary_is_fresh(root, &release_bin) {
        return Some(release_bin);
    }
    None
}

fn qypha_binary_is_fresh(root: &Path, binary: &Path) -> bool {
    let Ok(binary_meta) = fs::metadata(binary) else {
        return false;
    };
    let Ok(binary_modified) = binary_meta.modified() else {
        return false;
    };

    let manifest = root.join("Cargo.toml");
    if fs::metadata(&manifest)
        .and_then(|meta| meta.modified())
        .map(|modified| modified > binary_modified)
        .unwrap_or(false)
    {
        return false;
    }

    !tree_has_newer_entries(&root.join("src"), binary_modified)
}

fn tree_has_newer_entries(dir: &Path, binary_modified: std::time::SystemTime) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if tree_has_newer_entries(&path, binary_modified) {
                return true;
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if fs::metadata(&path)
            .and_then(|meta| meta.modified())
            .map(|modified| modified > binary_modified)
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn build_qypha_command(root: &Path, args: Vec<String>) -> Result<(Command, String), String> {
    if args.is_empty() {
        return Err("internal error: empty command args".to_string());
    }
    if let Some(bin) = find_qypha_bin(root) {
        let mut cmd = Command::new(&bin);
        configure_qypha_child_process(&mut cmd);
        for arg in &args {
            cmd.arg(arg);
        }
        let desc = format!("{} {}", bin.display(), args.join(" "));
        Ok((cmd, desc))
    } else {
        let manifest = root.join("Cargo.toml");
        let mut cmd = Command::new("cargo");
        configure_qypha_child_process(&mut cmd);
        cmd.arg("run");
        cmd.arg("--manifest-path");
        cmd.arg(&manifest);
        cmd.arg("--bin");
        cmd.arg("qypha");
        cmd.arg("--");
        for arg in &args {
            cmd.arg(arg);
        }
        let desc = format!(
            "cargo run --manifest-path {} --bin qypha -- {}",
            manifest.display(),
            args.join(" ")
        );
        Ok((cmd, desc))
    }
}

fn configure_qypha_child_process(_cmd: &mut Command) {
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        _cmd.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }
}

fn push_log(runtime: &mut AgentRuntime, line: String) {
    if runtime.mode.eq_ignore_ascii_case("ghost") {
        return;
    }
    if runtime.logs.len() >= 1200 {
        runtime.logs.pop_front();
    }
    runtime
        .logs
        .push_back(rewrite_runtime_log_dids_for_display(&line));
}

fn rewrite_runtime_log_dids_for_display(line: &str) -> String {
    let mut rewritten = String::with_capacity(line.len());
    let mut cursor = 0usize;

    while let Some(offset) = line[cursor..].find("did:nxf:") {
        let start = cursor + offset;
        rewritten.push_str(&line[cursor..start]);

        let tail = &line[start..];
        let canonical = extract_visible_did(tail).unwrap_or_else(|| "did:nxf:".to_string());
        let end = canonical.len();
        if let Some(contact) = contact_did_from_canonical_did(&canonical) {
            rewritten.push_str(&contact);
        } else {
            rewritten.push_str(&canonical);
        }
        cursor = start + end;
    }

    rewritten.push_str(&line[cursor..]);
    rewritten
}

fn is_progress_transfer_event(event: &str) -> bool {
    matches!(event, "incoming_progress" | "outgoing_progress")
}

fn transfer_event_identity(
    direction: &str,
    session_id: Option<&str>,
    peer_did: Option<&str>,
    filename: Option<&str>,
) -> Option<String> {
    if let Some(session_id) = session_id.map(str::trim).filter(|value| !value.is_empty()) {
        return Some(format!("session:{direction}:{session_id}"));
    }
    let peer_did = peer_did.map(str::trim).filter(|value| !value.is_empty())?;
    let filename = filename
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("file");
    Some(format!("peer:{direction}:{peer_did}:{filename}"))
}

fn same_transfer_identity(a: &TransferRuntimeEvent, b: &TransferRuntimeEvent) -> bool {
    transfer_event_identity(
        &a.direction,
        a.session_id.as_deref(),
        canonical_transfer_peer_did(a),
        a.filename.as_deref(),
    ) == transfer_event_identity(
        &b.direction,
        b.session_id.as_deref(),
        canonical_transfer_peer_did(b),
        b.filename.as_deref(),
    )
}

fn push_transfer_event(runtime: &mut AgentRuntime, event: TransferRuntimeEvent) {
    let is_progress = is_progress_transfer_event(&event.event);

    if is_progress {
        if let Some(existing) = runtime.transfer_events.iter_mut().rev().find(|existing| {
            is_progress_transfer_event(&existing.event) && same_transfer_identity(existing, &event)
        }) {
            *existing = event;
            return;
        }
    } else {
        runtime.transfer_events.retain(|existing| {
            !(is_progress_transfer_event(&existing.event)
                && same_transfer_identity(existing, &event))
        });
    }

    if runtime.transfer_events.len() >= 400 {
        runtime.transfer_events.pop_front();
    }
    runtime.transfer_events.push_back(event);
}

fn cleanup_transfer_event_sidechannel(runtime: &mut AgentRuntime) {
    if let Some(path) = runtime.transfer_event_file.take() {
        let _ = secure_wipe_file_local(&path);
    }
}

fn transfer_event_sidechannel_root() -> PathBuf {
    std::env::temp_dir().join("qypha-transfer")
}

fn create_transfer_event_sidechannel(agent_name: &str) -> Result<PathBuf, String> {
    let sanitized = agent_name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    let root = transfer_event_sidechannel_root();
    fs::create_dir_all(&root).map_err(|e| {
        format!(
            "transfer event sidechannel directory init failed '{}': {}",
            root.display(),
            e
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
    }

    let path = root.join(format!(
        "events-{}-{}-{}.jsonl",
        sanitized,
        std::process::id(),
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_micros())
    ));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("transfer event sidechannel init failed: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn wipe_ghost_runtime_buffers(runtime: &mut AgentRuntime) {
    if !runtime.mode.eq_ignore_ascii_case("ghost") {
        return;
    }
    runtime.logs.clear();
    runtime.transfer_events.clear();
    runtime.direct_events.clear();
    runtime.peer_events.clear();
    runtime.group_events.clear();
    runtime.peers.clear();
    runtime.pending_peers.clear();
    runtime.peer_refreshing = false;
    runtime.peer_revision = 0;
    runtime.mailbox_groups.clear();
    runtime.pending_mailbox_groups.clear();
    runtime.mailbox_group_refreshing = false;
    runtime.mailbox_group_revision = 0;
    runtime.pending_approvals.clear();
    runtime.did = None;
    runtime.pending_connected_peer_id = None;
    runtime.pending_verbose_name = None;
    runtime.pending_verbose_did = None;
    runtime.pending_verbose_peer_id = None;
    runtime.selected_peer = None;
    runtime.latest_invite_code = None;
    runtime.latest_invite_revision = 0;
    runtime.latest_invite_error = None;
    runtime.latest_invite_error_revision = 0;
    runtime.latest_group_invite_code = None;
    runtime.latest_group_invite_revision = 0;
    runtime.latest_group_invite_error = None;
    runtime.latest_group_invite_error_revision = 0;
    runtime.receive_dir = None;
    runtime.receive_dir_revision = 0;
    runtime.ghost_handoffs.clear();
    runtime.pending_invite_kind = None;
}

async fn pump_runtime_stream<R>(
    mut reader: R,
    manager: Arc<Mutex<RuntimeManager>>,
    app: tauri::AppHandle,
    agent_key: String,
    is_stderr: bool,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut read_buf = [0u8; 4096];
    let mut pending: Vec<u8> = Vec::with_capacity(4096);

    loop {
        match reader.read(&mut read_buf).await {
            Ok(0) => break,
            Ok(n) => {
                for &b in &read_buf[..n] {
                    if b == b'\n' || b == b'\r' {
                        if pending.is_empty() {
                            continue;
                        }
                        let mut line = String::from_utf8_lossy(&pending).to_string();
                        pending.clear();
                        if is_stderr {
                            line = format!("[stderr] {}", line);
                        }
                        ingest_emit_runtime_line(&manager, &app, &agent_key, line).await;
                    } else {
                        pending.push(b);
                    }
                }
            }
            Err(_) => break,
        }
    }

    if !pending.is_empty() {
        let mut line = String::from_utf8_lossy(&pending).to_string();
        if is_stderr {
            line = format!("[stderr] {}", line);
        }
        ingest_emit_runtime_line(&manager, &app, &agent_key, line).await;
    }
}

async fn ingest_emit_runtime_line(
    manager: &Arc<Mutex<RuntimeManager>>,
    app: &tauri::AppHandle,
    agent_key: &str,
    line: String,
) {
    let parsed_transfer = parse_transfer_event_line(&line);

    let mut ingested = false;
    let mut ingested_events = IngestedRuntimeEvents::default();
    {
        let mut guard = manager.lock().await;
        if let Some(rt) = guard.runtimes.get_mut(agent_key) {
            ingested_events = ingest_runtime_line(rt, line.clone());
            ingested = true;
        }
    }
    if ingested {
        let _ = app.emit(
            "qypha://runtime-line",
            RuntimeLineEvent {
                agent: agent_key.to_string(),
            },
        );

        for payload in ingested_events.ghost_events {
            let _ = app.emit("qypha://ghost-event", payload);
        }
        for payload in ingested_events.direct_events {
            let _ = app.emit("qypha://direct-message-event", payload);
        }
        for payload in ingested_events.peer_events {
            let _ = app.emit("qypha://peer-event", payload);
        }
        for payload in ingested_events.group_events {
            let _ = app.emit(
                "qypha://group-event",
                NamedGroupMailboxRuntimeEvent {
                    agent: agent_key.to_string(),
                    event: payload,
                },
            );
        }
    }

    if let Some(payload) = parsed_transfer {
        ingest_transfer_payload(manager, app, agent_key, payload).await;
    }
}

async fn ingest_transfer_payload(
    manager: &Arc<Mutex<RuntimeManager>>,
    app: &tauri::AppHandle,
    agent_key: &str,
    payload: TransferEventPayload,
) {
    {
        let mut guard = manager.lock().await;
        if let Some(rt) = guard.runtimes.get_mut(agent_key) {
            let canonical_did = payload
                .peer_did
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let contact_did = canonical_did.as_deref().and_then(|did| {
                rt.peers
                    .get(did)
                    .and_then(|peer| peer.contact_did.clone())
                    .or_else(|| contact_did_from_canonical_did(did))
            });
            let transfer_event = TransferRuntimeEvent {
                agent: agent_key.to_string(),
                event: payload.event.clone(),
                direction: payload.direction.clone(),
                peer_did: contact_did.clone().or_else(|| canonical_did.clone()),
                peer_contact_did: contact_did,
                peer_canonical_did: canonical_did,
                peer_name: payload.peer_name.clone(),
                session_id: payload.session_id.clone(),
                filename: payload.filename.clone(),
                reason: payload.reason.clone(),
                handoff_id: payload.handoff_id.clone(),
                group_id: payload.group_id.clone(),
                group_name: payload.group_name.clone(),
                transferred_chunks: payload.transferred_chunks,
                total_chunks: payload.total_chunks,
                transferred_bytes: payload.transferred_bytes,
                total_bytes: payload.total_bytes,
                percent: payload.percent,
                ts_ms: payload
                    .ts_ms
                    .unwrap_or_else(|| Utc::now().timestamp_millis()),
            };
            apply_transfer_event_to_runtime(rt, &payload, Some(transfer_event.clone()));
            if !rt.mode.eq_ignore_ascii_case("ghost") {
                if let Ok(json) = serde_json::to_string(&transfer_event) {
                    push_log(rt, format!("TRANSFER_EVENT {}", json));
                }
            }
            drop(guard);
            let _ = app.emit("qypha://transfer-event", transfer_event);
            return;
        } else {
            return;
        }
    }
}

async fn pump_transfer_event_file(
    manager: Arc<Mutex<RuntimeManager>>,
    app: tauri::AppHandle,
    agent_key: String,
    path: PathBuf,
) {
    let mut offset = 0u64;
    let mut pending = String::new();

    loop {
        let mut saw_bytes = false;
        if let Ok(mut file) = tokio::fs::OpenOptions::new().read(true).open(&path).await {
            if file.seek(SeekFrom::Start(offset)).await.is_ok() {
                let mut buf = String::new();
                if file.read_to_string(&mut buf).await.is_ok() && !buf.is_empty() {
                    offset = offset.saturating_add(buf.len() as u64);
                    pending.push_str(&buf);
                    saw_bytes = true;

                    while let Some(idx) = pending.find('\n') {
                        let line = pending[..idx].trim().to_string();
                        pending.drain(..=idx);
                        if line.is_empty() {
                            continue;
                        }
                        if let Some(payload) = parse_transfer_event_json_line(&line) {
                            ingest_transfer_payload(&manager, &app, &agent_key, payload).await;
                        }
                    }
                }
            }
        }

        let keep_running = {
            let guard = manager.lock().await;
            guard
                .runtimes
                .get(&agent_key)
                .map(|rt| {
                    rt.child.is_some()
                        && rt
                            .transfer_event_file
                            .as_deref()
                            .map(|current| current == path.as_path())
                            .unwrap_or(false)
                })
                .unwrap_or(false)
        };

        if !keep_running {
            if !pending.trim().is_empty() {
                let line = pending.trim().to_string();
                pending.clear();
                if let Some(payload) = parse_transfer_event_json_line(&line) {
                    ingest_transfer_payload(&manager, &app, &agent_key, payload).await;
                }
            }
            if !saw_bytes {
                break;
            }
        }

        sleep(Duration::from_millis(35)).await;
    }

    let _ = secure_wipe_file_local(&path);
}

fn ingest_runtime_line(runtime: &mut AgentRuntime, line: String) -> IngestedRuntimeEvents {
    let normalized = strip_ansi_codes(&line);
    let mut events = IngestedRuntimeEvents::default();
    if normalized.trim().is_empty() {
        return events;
    }
    if parse_transfer_event_line(&line).is_some() {
        return events;
    }
    if normalized == "DIRECT_PEERS_BEGIN" {
        runtime.pending_peers.clear();
        runtime.peer_refreshing = true;
        return events;
    }
    if normalized == "DIRECT_PEERS_EMPTY" {
        retain_reconnecting_peers(runtime);
        runtime.pending_peers.clear();
        runtime.peer_refreshing = false;
        runtime.peer_revision = runtime.peer_revision.saturating_add(1);
        clear_pending_verbose_peer(runtime);
        return events;
    }
    if normalized == "DIRECT_PEERS_END" {
        apply_pending_peer_refresh(runtime);
        runtime.peer_refreshing = false;
        runtime.peer_revision = runtime.peer_revision.saturating_add(1);
        return events;
    }
    if let Some(peer) = parse_headless_direct_peer_json_line(&normalized) {
        if runtime.peer_refreshing {
            stage_pending_peer(runtime, peer);
        } else {
            upsert_headless_peer(runtime, peer);
            runtime.peer_revision = runtime.peer_revision.saturating_add(1);
        }
        return events;
    }
    if normalized == "MAILBOX_GROUPS_BEGIN" {
        runtime.pending_mailbox_groups.clear();
        runtime.mailbox_group_refreshing = true;
        return events;
    }
    if normalized == "MAILBOX_GROUPS_EMPTY" {
        runtime.mailbox_groups.clear();
        runtime.pending_mailbox_groups.clear();
        runtime.mailbox_group_refreshing = false;
        runtime.mailbox_group_revision = runtime.mailbox_group_revision.saturating_add(1);
        return events;
    }
    if normalized == "MAILBOX_GROUPS_END" {
        runtime
            .pending_mailbox_groups
            .sort_by(|a, b| a.group_id.cmp(&b.group_id));
        runtime.mailbox_groups = std::mem::take(&mut runtime.pending_mailbox_groups);
        runtime.mailbox_group_refreshing = false;
        runtime.mailbox_group_revision = runtime.mailbox_group_revision.saturating_add(1);
        return events;
    }
    if let Some(group) = parse_mailbox_group_json_line(&normalized) {
        if runtime.mailbox_group_refreshing {
            runtime.pending_mailbox_groups.push(group);
        } else {
            upsert_mailbox_group(runtime, group);
        }
        return events;
    }
    if let Some(result) = parse_headless_invite_result_json_line(&normalized) {
        apply_headless_invite_result(runtime, result, &mut events.ghost_events);
        return events;
    }
    if let Some(direct_event) = parse_direct_message_event_json_line(&normalized) {
        apply_direct_message_event_to_runtime(runtime, direct_event.clone());
        if runtime.mode.eq_ignore_ascii_case("ghost") && direct_event.direction == "incoming" {
            events.ghost_events.push(GhostRuntimeEvent {
                agent: runtime.name.clone(),
                event: "incoming_chat".to_string(),
                sender: Some(direct_event.peer_name.clone()),
                message: Some(direct_event.message.clone()),
                kind: None,
                code: None,
                revision: None,
            });
        }
        events.direct_events.push(direct_event);
        return events;
    }
    if let Some(peer_event) = parse_direct_peer_event_json_line(&normalized) {
        apply_direct_peer_event_to_runtime(runtime, peer_event.clone());
        events.peer_events.push(peer_event);
        return events;
    }
    if let Some(group_event) = parse_group_mailbox_event_json_line(&normalized) {
        apply_group_event_to_runtime(runtime, group_event.clone());
        events.group_events.push(group_event);
        return events;
    }
    if let Some(policy) = parse_handshake_request_policy_json_line(&normalized) {
        apply_handshake_request_policy_to_runtime(runtime, policy);
        return events;
    }
    if let Some(policy) = parse_incoming_connect_policy_json_line(&normalized) {
        apply_incoming_connect_policy_to_runtime(runtime, policy);
        return events;
    }
    if let Some(request) = parse_pending_contact_request_line(&normalized) {
        upsert_pending_contact_request(runtime, request);
    }
    if let Some((accepted, did, contact_did, name)) =
        parse_contact_request_resolution_line(&normalized)
    {
        if accepted {
            let pending = runtime.pending_contact_requests.get(&did).cloned();
            let resolved_name = pending
                .as_ref()
                .map(|request| request.name.clone())
                .or(name);
            let resolved_contact_did = pending
                .as_ref()
                .and_then(|request| request.contact_did.clone())
                .or(contact_did);
            upsert_known_peer(
                runtime,
                &did,
                resolved_contact_did,
                resolved_name,
                "connecting",
                true,
            );
            runtime.peer_revision = runtime.peer_revision.saturating_add(1);
        }
        drop_pending_contact_request(runtime, &did);
    }
    if invite_banner_matches(&normalized, PendingInviteKind::Group) {
        runtime.pending_invite_kind = Some(PendingInviteKind::Group);
    } else if invite_banner_matches(&normalized, PendingInviteKind::Direct) {
        runtime.pending_invite_kind = Some(PendingInviteKind::Direct);
    }

    if let Some(path) = parse_receive_dir_line(&normalized) {
        runtime.receive_dir = Some(path);
        runtime.receive_dir_revision = runtime.receive_dir_revision.saturating_add(1);
    }

    if let Some(kind) = runtime.pending_invite_kind {
        if let Some(code) = extract_invite_token(&normalized) {
            match kind {
                PendingInviteKind::Direct => {
                    runtime.latest_invite_code = Some(code.clone());
                    runtime.latest_invite_revision =
                        runtime.latest_invite_revision.saturating_add(1);
                }
                PendingInviteKind::Group => {
                    runtime.latest_group_invite_code = Some(code.clone());
                    runtime.latest_group_invite_revision =
                        runtime.latest_group_invite_revision.saturating_add(1);
                }
            }
            events.ghost_events.push(GhostRuntimeEvent {
                agent: runtime.name.clone(),
                event: "invite_code".to_string(),
                sender: None,
                message: None,
                kind: Some(match kind {
                    PendingInviteKind::Direct => "direct".to_string(),
                    PendingInviteKind::Group => "group".to_string(),
                }),
                code: Some(code),
                revision: Some(match kind {
                    PendingInviteKind::Direct => runtime.latest_invite_revision,
                    PendingInviteKind::Group => runtime.latest_group_invite_revision,
                }),
            });
            runtime.pending_invite_kind = None;
        } else if invite_completion_matches(&normalized, kind) {
            runtime.pending_invite_kind = None;
        }
    }

    if runtime.mode.eq_ignore_ascii_case("ghost") {
        if let Some((sender, message)) = parse_incoming_chat(&normalized) {
            events.ghost_events.push(GhostRuntimeEvent {
                agent: runtime.name.clone(),
                event: "incoming_chat".to_string(),
                sender: Some(sender),
                message: Some(message),
                kind: None,
                code: None,
                revision: None,
            });
        }
    }
    if normalized.contains("connection established") || normalized.contains("Connected to ") {
        if let Some(pid) = extract_peer_id(&normalized) {
            runtime.pending_connected_peer_id = Some(pid);
        }
    }
    if let Some((name, pid)) = parse_peers_verbose_header(&normalized) {
        runtime.pending_verbose_name = Some(name);
        runtime.pending_verbose_peer_id = pid;
        runtime.pending_verbose_did = None;
    }
    if normalized.contains("No peers connected.") {
        retain_reconnecting_peers(runtime);
        clear_pending_verbose_peer(runtime);
    }
    if normalized.contains("No known direct peers yet.") {
        runtime.peers.clear();
        runtime.pending_approvals.clear();
        runtime.selected_peer = None;
        clear_pending_verbose_peer(runtime);
    }
    if normalized.contains("Disconnecting:") || normalized.contains("disconnect requested for") {
        if let Some(did) = extract_did(&normalized) {
            drop_peer(runtime, &did);
        }
    }
    if normalized.contains("Peer connected:") {
        if let Some((name, did)) = parse_peer_connected(&normalized) {
            let peer_id = runtime.pending_connected_peer_id.take();
            drop_pending_contact_request(runtime, &did);
            runtime.peers.insert(
                did.clone(),
                PeerRuntime {
                    name,
                    contact_did: contact_did_from_canonical_did(&did),
                    did,
                    peer_id,
                    status: "connected".to_string(),
                    auto_reconnect: false,
                },
            );
        }
    }
    if normalized.contains("DID:") {
        if let Some(did) = extract_did(&normalized) {
            if let Some(name) = runtime.pending_verbose_name.clone() {
                runtime.pending_verbose_did = Some(did.clone());
                let peer_id = runtime.pending_verbose_peer_id.clone();
                runtime.peers.insert(
                    did.clone(),
                    PeerRuntime {
                        name,
                        contact_did: contact_did_from_canonical_did(&did),
                        did,
                        peer_id,
                        status: "ready".to_string(),
                        auto_reconnect: false,
                    },
                );
            } else {
                runtime.did = Some(did);
            }
        }
    }
    if normalized.contains("Peer ID:") {
        if runtime.pending_verbose_name.is_some() {
            if let (Some(did), Some(peer_id)) = (
                runtime.pending_verbose_did.clone(),
                extract_peer_id(&normalized),
            ) {
                if let Some(peer) = runtime.peers.get_mut(&did) {
                    peer.peer_id = Some(peer_id);
                }
            }
            clear_pending_verbose_peer(runtime);
        }
    }
    if normalized.contains("Peer disconnected:") {
        if let Some(did) = extract_did(&normalized) {
            if !should_preserve_reconnecting_peer_did(runtime, &did) {
                mark_peer_offline(runtime, &did, None);
            }
        } else if let Some(peer_id) = extract_peer_id(&normalized) {
            if !should_preserve_reconnecting_peer_id(runtime, &peer_id) {
                if let Some(did) = find_did_by_peer_id(runtime, &peer_id) {
                    mark_peer_offline(runtime, &did, Some(peer_id));
                }
            }
        } else if runtime.peers.len() <= 1 && !runtime.peers.values().any(is_reconnecting_peer) {
            for peer in runtime.peers.values_mut() {
                peer.status = "offline".to_string();
            }
        }
    }
    if normalized.contains("Connection closed peer_id=") {
        if let Some(peer_id) = extract_peer_id(&normalized) {
            if !should_preserve_reconnecting_peer_id(runtime, &peer_id) {
                if let Some(did) = find_did_by_peer_id(runtime, &peer_id) {
                    mark_peer_offline(runtime, &did, Some(peer_id));
                }
            }
        }
    }
    if let Some(parsed) = parse_peers_listing(&normalized) {
        let peer = PeerRuntime {
            name: parsed.name,
            contact_did: contact_did_from_canonical_did(&parsed.did),
            did: parsed.did,
            peer_id: runtime.pending_connected_peer_id.clone(),
            status: parsed.status,
            auto_reconnect: parsed.auto_reconnect,
        };
        if runtime.peer_refreshing {
            if let Some(existing) = runtime
                .pending_peers
                .iter_mut()
                .find(|existing| existing.did == peer.did)
            {
                *existing = peer;
            } else {
                runtime.pending_peers.push(peer);
            }
        } else {
            runtime.peers.insert(peer.did.clone(), peer);
        }
    }
    // Parse auto-reconnect toggle response: AUTO_RECONNECT_SET:<did>:<true|false>
    if normalized.starts_with("AUTO_RECONNECT_SET:") {
        let rest = &normalized["AUTO_RECONNECT_SET:".len()..];
        if let Some((did, val)) = rest.rsplit_once(':') {
            let enabled = val.trim() == "true";
            let canonical_did = normalize_peer_selector(did);
            if let Some(peer) = runtime.peers.get_mut(&canonical_did) {
                peer.auto_reconnect = enabled;
            }
        }
    }
    if normalized.contains("Incoming chunked transfer pending approval:") {
        if let Some(did) = extract_did(&normalized) {
            if !runtime.pending_approvals.contains(&did) {
                runtime.pending_approvals.push(did);
            }
        }
    }
    if should_suppress_runtime_log(runtime, &normalized) {
        return events;
    }
    if let Some(redacted) = redact_group_offer_line(&normalized) {
        push_log(runtime, redacted);
    } else {
        push_log(runtime, normalized);
    }
    events
}

fn apply_transfer_event_to_runtime(
    runtime: &mut AgentRuntime,
    payload: &TransferEventPayload,
    transfer_event: Option<TransferRuntimeEvent>,
) {
    if let Some(event) = transfer_event {
        push_transfer_event(runtime, event);
        recompute_pending_approvals_from_transfer_events(runtime);
    }

    match payload.event.as_str() {
        "incoming_staged" if runtime.mode.eq_ignore_ascii_case("ghost") => {
            let Some(handoff_id) = payload
                .handoff_id
                .as_ref()
                .filter(|value| !value.trim().is_empty())
            else {
                return;
            };
            let Some(handoff_path) = payload
                .handoff_path
                .as_ref()
                .map(PathBuf::from)
                .filter(|path| !path.as_os_str().is_empty())
            else {
                return;
            };
            let peer_did = payload
                .peer_did
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "did:nxf:unknown".to_string());
            let peer_name = payload
                .peer_name
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| peer_did.clone());
            let filename = payload
                .filename
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "received-file".to_string());
            runtime.ghost_handoffs.insert(
                handoff_id.clone(),
                GhostHandoff {
                    handoff_id: handoff_id.clone(),
                    peer_did,
                    peer_name,
                    filename,
                    staged_path: handoff_path,
                    created_at_ms: payload
                        .ts_ms
                        .unwrap_or_else(|| Utc::now().timestamp_millis()),
                },
            );
        }
        _ => {}
    }
}

fn drop_peer(runtime: &mut AgentRuntime, did: &str) {
    runtime.peers.remove(did);
    runtime.pending_approvals.retain(|v| v != did);
    drop_pending_contact_request(runtime, did);
    if runtime.selected_peer.as_deref() == Some(did) {
        runtime.selected_peer = None;
    }
}

fn mark_peer_offline(runtime: &mut AgentRuntime, did: &str, peer_id: Option<String>) {
    if let Some(peer) = runtime.peers.get_mut(did) {
        peer.status = "offline".to_string();
        if peer.peer_id.is_none() {
            peer.peer_id = peer_id;
        }
    }
}

fn peer_status_should_upgrade(current_status: &str, next_status: &str) -> bool {
    let current = current_status.trim().to_ascii_lowercase();
    let next = next_status.trim().to_ascii_lowercase();
    if next.is_empty() {
        return false;
    }
    matches!(next.as_str(), "ready" | "connected" | "online")
        || current.is_empty()
        || matches!(current.as_str(), "offline" | "connecting" | "reconnecting")
}

fn merge_peer_runtime(existing: &mut PeerRuntime, incoming: PeerRuntime) {
    if !incoming.name.trim().is_empty() {
        existing.name = incoming.name.trim().to_string();
    }
    if incoming.contact_did.is_some() {
        existing.contact_did = incoming.contact_did;
    }
    if incoming.peer_id.is_some() {
        existing.peer_id = incoming.peer_id;
    }
    if incoming.auto_reconnect {
        existing.auto_reconnect = true;
    }
    if peer_status_should_upgrade(&existing.status, &incoming.status) {
        existing.status = incoming.status.trim().to_string();
    }
}

fn stage_pending_known_peer(runtime: &mut AgentRuntime, peer: &PeerRuntime) {
    if !runtime.peer_refreshing {
        return;
    }
    if let Some(existing) = runtime
        .pending_peers
        .iter_mut()
        .find(|existing| existing.did == peer.did)
    {
        merge_peer_runtime(existing, peer.clone());
        return;
    }
    runtime.pending_peers.push(peer.clone());
}

fn upsert_known_peer(
    runtime: &mut AgentRuntime,
    canonical_did: &str,
    contact_did: Option<String>,
    name: Option<String>,
    status: &str,
    auto_reconnect: bool,
) {
    let fallback_name = name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .or_else(|| contact_did.clone())
        .unwrap_or_else(|| canonical_did.to_string());
    let next_status = status.trim();
    let incoming = PeerRuntime {
        name: fallback_name,
        did: canonical_did.to_string(),
        contact_did,
        peer_id: None,
        status: if next_status.is_empty() {
            "offline".to_string()
        } else {
            next_status.to_string()
        },
        auto_reconnect,
    };

    match runtime.peers.get_mut(canonical_did) {
        Some(peer) => {
            merge_peer_runtime(peer, incoming.clone());
        }
        None => {
            runtime
                .peers
                .insert(canonical_did.to_string(), incoming.clone());
        }
    }
    stage_pending_known_peer(runtime, &incoming);
}

fn should_preserve_reconnecting_peer_did(runtime: &AgentRuntime, did: &str) -> bool {
    runtime.peers.get(did).is_some_and(is_reconnecting_peer)
}

fn should_preserve_reconnecting_peer_id(runtime: &AgentRuntime, peer_id: &str) -> bool {
    runtime
        .peers
        .values()
        .any(|peer| peer.peer_id.as_deref() == Some(peer_id) && is_reconnecting_peer(peer))
}

fn clear_pending_verbose_peer(runtime: &mut AgentRuntime) {
    runtime.pending_verbose_name = None;
    runtime.pending_verbose_did = None;
    runtime.pending_verbose_peer_id = None;
}

fn find_did_by_peer_id(runtime: &AgentRuntime, peer_id: &str) -> Option<String> {
    runtime
        .peers
        .values()
        .find(|p| p.peer_id.as_deref() == Some(peer_id))
        .map(|p| p.did.clone())
}

fn transfer_runtime_event_key(event: &TransferRuntimeEvent) -> Option<String> {
    let did = canonical_transfer_peer_did(event)?.trim();
    if did.is_empty() {
        return None;
    }
    let direction = event.direction.trim();
    let session_id = event.session_id.as_deref().unwrap_or("").trim();
    if !session_id.is_empty() {
        return Some(session_id.to_string());
    }
    let filename = event.filename.as_deref().unwrap_or("").trim();
    Some(format!("{direction}:{did}:{filename}"))
}

fn recompute_pending_approvals_from_transfer_events(runtime: &mut AgentRuntime) {
    let mut latest_by_key: HashMap<String, TransferRuntimeEvent> = HashMap::new();
    for event in runtime.transfer_events.iter() {
        let is_incoming = matches!(event.direction.as_str(), "incoming" | "in");
        if !is_incoming {
            continue;
        }
        let Some(key) = transfer_runtime_event_key(event) else {
            continue;
        };
        latest_by_key.insert(key, event.clone());
    }

    let mut pending: Vec<String> = latest_by_key
        .into_values()
        .filter(|event| event.event == "incoming_pending")
        .filter_map(|event| event.peer_canonical_did.or(event.peer_did))
        .map(|did| did.trim().to_string())
        .filter(|did| !did.is_empty())
        .collect();
    pending.sort();
    pending.dedup();
    runtime.pending_approvals = pending;
}

fn parse_peer_connected(line: &str) -> Option<(String, String)> {
    let rest = line.split("Peer connected:").nth(1)?.trim();
    let did = extract_did(rest)?;
    let name = rest.split(" (did:").next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some((name, did))
    }
}

fn parse_peers_verbose_header(line: &str) -> Option<(String, Option<String>)> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix('[') {
        let close = rest.find(']')?;
        let after = rest[(close + 1)..].trim_start();
        let name = after.split(" — ").next().unwrap_or("").trim().to_string();
        if !name.is_empty() {
            return Some((name, None));
        }
    }
    let dot = t.find(". ")?;
    if !t[..dot].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let after = &t[(dot + 2)..];
    if let Some(open) = after.rfind('[') {
        if after.ends_with(']') && open > 0 {
            let name = after[..open].trim().to_string();
            let peer_id = after[(open + 1)..(after.len() - 1)].trim().to_string();
            if !name.is_empty() {
                return Some((name, (!peer_id.is_empty()).then_some(peer_id)));
            }
        }
    }
    None
}

fn strip_ansi_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                while let Some(c) = chars.next() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn parse_transfer_event_line(line: &str) -> Option<TransferEventPayload> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let marker = "TRANSFER_EVENT ";
    let idx = without_stderr.find(marker)?;
    parse_transfer_event_json_line(without_stderr[(idx + marker.len())..].trim())
}

fn parse_transfer_event_json_line(line: &str) -> Option<TransferEventPayload> {
    serde_json::from_str::<TransferEventPayload>(line.trim()).ok()
}

fn parse_direct_message_event_json_line(line: &str) -> Option<DirectMessageRuntimeEvent> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let marker = "DIRECT_MESSAGE_EVENT ";
    let idx = without_stderr.find(marker)?;
    let mut event = serde_json::from_str::<DirectMessageRuntimeEvent>(
        without_stderr[(idx + marker.len())..].trim(),
    )
    .ok()?;
    if event.ts_ms == 0 {
        event.ts_ms = Utc::now().timestamp_millis();
    }
    let canonical_did =
        resolve_canonical_did(&event.peer_did, event.peer_canonical_did.as_deref())?;
    let contact_did = resolve_contact_did(
        &event.peer_did,
        event.peer_contact_did.as_deref(),
        &canonical_did,
    )?;
    event.peer_did = contact_did.clone();
    event.peer_contact_did = Some(contact_did);
    event.peer_canonical_did = Some(canonical_did);
    if event.peer_did.trim().is_empty() || event.message.trim().is_empty() {
        return None;
    }
    Some(event)
}

fn parse_direct_peer_event_json_line(line: &str) -> Option<DirectPeerRuntimeEvent> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let marker = "DIRECT_PEER_EVENT ";
    let idx = without_stderr.find(marker)?;
    let mut event = serde_json::from_str::<DirectPeerRuntimeEvent>(
        without_stderr[(idx + marker.len())..].trim(),
    )
    .ok()?;
    if event.ts_ms == 0 {
        event.ts_ms = Utc::now().timestamp_millis();
    }
    let canonical_did = resolve_canonical_did(&event.did, event.canonical_did.as_deref())?;
    let contact_did =
        resolve_contact_did(&event.did, event.contact_did.as_deref(), &canonical_did)?;
    event.did = contact_did.clone();
    event.contact_did = Some(contact_did);
    event.canonical_did = Some(canonical_did);
    if event.did.trim().is_empty() {
        return None;
    }
    Some(event)
}

fn parse_headless_direct_peer_json_line(line: &str) -> Option<HeadlessDirectPeerSnapshot> {
    let payload = line.strip_prefix("DIRECT_PEER ")?;
    serde_json::from_str::<HeadlessDirectPeerSnapshot>(payload.trim()).ok()
}

fn parse_mailbox_group_json_line(line: &str) -> Option<MailboxGroupSnapshot> {
    let payload = line.strip_prefix("MAILBOX_GROUP ")?;
    serde_json::from_str::<MailboxGroupSnapshot>(payload.trim()).ok()
}

fn parse_headless_invite_result_json_line(line: &str) -> Option<HeadlessInviteResult> {
    let payload = line.strip_prefix("INVITE_RESULT ")?;
    serde_json::from_str::<HeadlessInviteResult>(payload.trim()).ok()
}

fn parse_group_mailbox_event_json_line(line: &str) -> Option<GroupMailboxRuntimeEvent> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let marker = "GROUP_MAILBOX_EVENT ";
    let idx = without_stderr.find(marker)?;
    let payload = without_stderr[(idx + marker.len())..].trim();
    let mut event = serde_json::from_str::<GroupMailboxRuntimeEvent>(payload).ok()?;
    if event.ts_ms == 0 {
        event.ts_ms = Utc::now().timestamp_millis();
    }
    Some(event)
}

fn parse_handshake_request_policy_json_line(line: &str) -> Option<HandshakeRequestPolicySnapshot> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let marker = "HANDSHAKE_REQUEST_POLICY ";
    let idx = without_stderr.find(marker)?;
    serde_json::from_str::<HandshakeRequestPolicySnapshot>(
        without_stderr[(idx + marker.len())..].trim(),
    )
    .ok()
}

fn parse_incoming_connect_policy_json_line(line: &str) -> Option<IncomingConnectPolicySnapshot> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let marker = "INCOMING_CONNECT_POLICY ";
    let idx = without_stderr.find(marker)?;
    serde_json::from_str::<IncomingConnectPolicySnapshot>(
        without_stderr[(idx + marker.len())..].trim(),
    )
    .ok()
}

fn extract_visible_did(text: &str) -> Option<String> {
    if let Some(start) = text.find("did:qypha:") {
        let tail = &text[start..];
        let suffix = &tail["did:qypha:".len()..];
        let len = suffix
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_alphanumeric())
            .map(|(idx, _)| idx)
            .unwrap_or_else(|| suffix.len());
        if len > 0 {
            return Some(format!("did:qypha:{}", &suffix[..len]));
        }
    }
    if let Some(start) = text.find("did:nxf:") {
        let tail = &text[start..];
        let suffix = &tail["did:nxf:".len()..];
        let len = suffix
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_lowercase() && !ch.is_ascii_digit())
            .map(|(idx, _)| idx)
            .unwrap_or_else(|| suffix.len());
        if len > 0 {
            return Some(format!("did:nxf:{}", &suffix[..len]));
        }
    }
    None
}

fn parse_pending_contact_request_line(line: &str) -> Option<PendingContactRequestRuntime> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let rest = without_stderr.split("Contact request:").nth(1)?.trim();
    let visible_did = extract_visible_did(rest)?;
    let canonical_did =
        canonical_did_from_contact_did(&visible_did).unwrap_or_else(|| visible_did.clone());
    let contact_did = resolve_contact_did(&visible_did, Some(&visible_did), &canonical_did)
        .or_else(|| contact_did_from_canonical_did(&canonical_did));
    let name = rest.split(" (").next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some(PendingContactRequestRuntime {
        name,
        did: canonical_did,
        contact_did,
        ts_ms: Utc::now().timestamp_millis(),
    })
}

fn parse_contact_request_resolution_line(
    line: &str,
) -> Option<(bool, String, Option<String>, Option<String>)> {
    let normalized = strip_ansi_codes(line);
    let without_stderr = normalized
        .strip_prefix("[stderr] ")
        .unwrap_or(&normalized)
        .trim();
    let (accepted, rest) = if let Some(rest) = without_stderr.split("Contact accepted:").nth(1) {
        (true, rest.trim())
    } else if let Some(rest) = without_stderr.split("Contact rejected:").nth(1) {
        (false, rest.trim())
    } else {
        return None;
    };
    let visible_did = extract_visible_did(without_stderr)?;
    let canonical_did =
        canonical_did_from_contact_did(&visible_did).unwrap_or_else(|| visible_did.clone());
    let contact_did = resolve_contact_did(&visible_did, Some(&visible_did), &canonical_did)
        .or_else(|| contact_did_from_canonical_did(&canonical_did));
    let name = rest
        .split(" (")
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    Some((accepted, canonical_did, contact_did, name))
}

fn upsert_pending_contact_request(
    runtime: &mut AgentRuntime,
    request: PendingContactRequestRuntime,
) {
    runtime
        .pending_contact_requests
        .insert(request.did.clone(), request);
}

fn drop_pending_contact_request(runtime: &mut AgentRuntime, did: &str) {
    runtime.pending_contact_requests.remove(did);
}

fn push_group_event(runtime: &mut AgentRuntime, event: GroupMailboxRuntimeEvent) {
    if runtime.group_events.len() >= 400 {
        runtime.group_events.pop_front();
    }
    runtime.group_events.push_back(event);
}

fn push_direct_event(runtime: &mut AgentRuntime, event: DirectMessageRuntimeEvent) {
    if runtime.direct_events.len() >= 600 {
        runtime.direct_events.pop_front();
    }
    runtime.direct_events.push_back(event);
}

fn push_peer_event(runtime: &mut AgentRuntime, event: DirectPeerRuntimeEvent) {
    if runtime.peer_events.len() >= 300 {
        runtime.peer_events.pop_front();
    }
    runtime.peer_events.push_back(event);
}

fn apply_direct_message_event_to_runtime(
    runtime: &mut AgentRuntime,
    event: DirectMessageRuntimeEvent,
) {
    let canonical_did = resolve_canonical_did(&event.peer_did, event.peer_canonical_did.as_deref())
        .unwrap_or_else(|| event.peer_did.clone());
    let contact_did = resolve_contact_did(
        &event.peer_did,
        event.peer_contact_did.as_deref(),
        &canonical_did,
    );
    let auto_reconnect = runtime
        .peers
        .get(&canonical_did)
        .map(|existing| existing.auto_reconnect)
        .unwrap_or(true);
    upsert_known_peer(
        runtime,
        &canonical_did,
        contact_did,
        Some(event.peer_name.clone()),
        "ready",
        auto_reconnect,
    );
    drop_pending_contact_request(runtime, &canonical_did);
    runtime.peer_revision = runtime.peer_revision.saturating_add(1);
    push_direct_event(runtime, event);
}

fn apply_direct_peer_event_to_runtime(runtime: &mut AgentRuntime, event: DirectPeerRuntimeEvent) {
    let canonical_did = resolve_canonical_did(&event.did, event.canonical_did.as_deref())
        .unwrap_or_else(|| event.did.clone());
    let contact_did = resolve_contact_did(&event.did, event.contact_did.as_deref(), &canonical_did);
    let auto_reconnect = runtime
        .peers
        .get(&canonical_did)
        .map(|existing| existing.auto_reconnect)
        .unwrap_or(false);

    match event.event.as_str() {
        "connected" | "reconnecting" => {
            runtime.peers.insert(
                canonical_did.clone(),
                PeerRuntime {
                    name: if event.name.trim().is_empty() {
                        contact_did.clone().unwrap_or_else(|| canonical_did.clone())
                    } else {
                        event.name.clone()
                    },
                    did: canonical_did.clone(),
                    contact_did,
                    peer_id: event.peer_id.clone(),
                    status: if event.status.trim().is_empty() {
                        if event.event == "reconnecting" {
                            "reconnecting".to_string()
                        } else {
                            "connected".to_string()
                        }
                    } else {
                        event.status.clone()
                    },
                    auto_reconnect: auto_reconnect || event.event == "reconnecting",
                },
            );
        }
        "disconnected" => {
            if event
                .reason
                .as_deref()
                .is_some_and(|reason| reason.eq_ignore_ascii_case("manual_disconnect"))
            {
                drop_peer(runtime, &canonical_did);
            } else {
                mark_peer_offline(runtime, &canonical_did, event.peer_id.clone());
            }
        }
        _ => {}
    }

    runtime.peer_revision = runtime.peer_revision.saturating_add(1);
    push_peer_event(runtime, event);
}

fn peer_runtime_from_headless(
    runtime: &AgentRuntime,
    peer: HeadlessDirectPeerSnapshot,
) -> PeerRuntime {
    let canonical_did = resolve_canonical_did(&peer.did, peer.canonical_did.as_deref())
        .unwrap_or_else(|| peer.did.clone());
    let contact_did = resolve_contact_did(&peer.did, peer.contact_did.as_deref(), &canonical_did);
    let existing = runtime.peers.get(&canonical_did);
    let auto_reconnect = existing
        .map(|current| current.auto_reconnect)
        .unwrap_or(false);
    PeerRuntime {
        name: peer.name,
        did: canonical_did,
        contact_did: contact_did
            .or_else(|| existing.and_then(|current| current.contact_did.clone())),
        peer_id: peer.peer_id,
        status: peer.status,
        auto_reconnect,
    }
}

fn stage_pending_peer(runtime: &mut AgentRuntime, peer: HeadlessDirectPeerSnapshot) {
    let peer = peer_runtime_from_headless(runtime, peer);
    if let Some(existing) = runtime
        .pending_peers
        .iter_mut()
        .find(|existing| existing.did == peer.did)
    {
        merge_peer_runtime(existing, peer);
        return;
    }
    runtime.pending_peers.push(peer);
}

fn upsert_headless_peer(runtime: &mut AgentRuntime, peer: HeadlessDirectPeerSnapshot) {
    let peer = peer_runtime_from_headless(runtime, peer);
    runtime.peers.insert(peer.did.clone(), peer);
}

fn is_reconnecting_peer(peer: &PeerRuntime) -> bool {
    peer.status.trim().eq_ignore_ascii_case("reconnecting")
}

fn retain_reconnecting_peers(runtime: &mut AgentRuntime) {
    runtime.peers.retain(|_, peer| is_reconnecting_peer(peer));
    runtime
        .pending_approvals
        .retain(|did| runtime.peers.contains_key(did));
    if runtime
        .selected_peer
        .as_deref()
        .is_some_and(|did| !runtime.peers.contains_key(did))
    {
        runtime.selected_peer = None;
    }
}

fn apply_pending_peer_refresh(runtime: &mut AgentRuntime) {
    let mut next = HashMap::new();
    for peer in std::mem::take(&mut runtime.pending_peers) {
        next.insert(peer.did.clone(), peer);
    }
    for (did, peer) in runtime.peers.iter() {
        if is_reconnecting_peer(peer) {
            next.entry(did.clone()).or_insert_with(|| peer.clone());
        }
    }
    runtime.peers = next;
    runtime
        .pending_approvals
        .retain(|did| runtime.peers.contains_key(did));
    if runtime
        .selected_peer
        .as_deref()
        .is_some_and(|did| !runtime.peers.contains_key(did))
    {
        runtime.selected_peer = None;
    }
}

fn upsert_mailbox_group(runtime: &mut AgentRuntime, group: MailboxGroupSnapshot) {
    if let Some(existing) = runtime
        .mailbox_groups
        .iter_mut()
        .find(|existing| existing.group_id == group.group_id)
    {
        *existing = group;
        let next_revision = runtime.mailbox_group_revision.saturating_add(1);
        runtime.mailbox_group_revision = next_revision;
        return;
    }
    runtime.mailbox_groups.push(group);
    runtime
        .mailbox_groups
        .sort_by(|a, b| a.group_id.cmp(&b.group_id));
    let next_revision = runtime.mailbox_group_revision.saturating_add(1);
    runtime.mailbox_group_revision = next_revision;
}

fn apply_headless_invite_result(
    runtime: &mut AgentRuntime,
    result: HeadlessInviteResult,
    ghost_events: &mut Vec<GhostRuntimeEvent>,
) {
    let kind = if result.kind.eq_ignore_ascii_case("group") {
        PendingInviteKind::Group
    } else {
        PendingInviteKind::Direct
    };

    if let Some(group) = result.group {
        upsert_mailbox_group(runtime, group);
    }

    if let Some(error) = result
        .error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        match kind {
            PendingInviteKind::Direct => {
                runtime.latest_invite_error = Some(error.to_string());
                runtime.latest_invite_error_revision =
                    runtime.latest_invite_error_revision.saturating_add(1);
            }
            PendingInviteKind::Group => {
                runtime.latest_group_invite_error = Some(error.to_string());
                runtime.latest_group_invite_error_revision =
                    runtime.latest_group_invite_error_revision.saturating_add(1);
            }
        }
    }

    if let Some(code) = result
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let code = code.to_string();
        match kind {
            PendingInviteKind::Direct => {
                runtime.latest_invite_code = Some(code.clone());
                runtime.latest_invite_revision = runtime.latest_invite_revision.saturating_add(1);
                runtime.latest_invite_error = None;
                ghost_events.push(GhostRuntimeEvent {
                    agent: runtime.name.clone(),
                    event: "invite_code".to_string(),
                    sender: None,
                    message: None,
                    kind: Some("direct".to_string()),
                    code: Some(code),
                    revision: Some(runtime.latest_invite_revision),
                });
            }
            PendingInviteKind::Group => {
                runtime.latest_group_invite_code = Some(code.clone());
                runtime.latest_group_invite_revision =
                    runtime.latest_group_invite_revision.saturating_add(1);
                runtime.latest_group_invite_error = None;
                ghost_events.push(GhostRuntimeEvent {
                    agent: runtime.name.clone(),
                    event: "invite_code".to_string(),
                    sender: None,
                    message: None,
                    kind: Some("group".to_string()),
                    code: Some(code),
                    revision: Some(runtime.latest_group_invite_revision),
                });
            }
        }
    }

    runtime.pending_invite_kind = None;
}

fn apply_handshake_request_policy_to_runtime(
    runtime: &mut AgentRuntime,
    mut policy: HandshakeRequestPolicySnapshot,
) {
    policy.blocked_member_ids.sort();
    policy.blocked_member_ids.dedup();
    runtime.handshake_request_policy = policy.clone();
    if policy.block_all {
        runtime
            .group_events
            .retain(|event| event.kind != "direct_handshake_offer");
        return;
    }
    if policy.blocked_member_ids.is_empty() {
        return;
    }
    let blocked = policy
        .blocked_member_ids
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    runtime.group_events.retain(|event| {
        !(event.kind == "direct_handshake_offer"
            && event
                .sender_member_id
                .as_ref()
                .map(|sender| blocked.contains(sender))
                .unwrap_or(false))
    });
}

fn apply_incoming_connect_policy_to_runtime(
    runtime: &mut AgentRuntime,
    mut policy: IncomingConnectPolicySnapshot,
) {
    policy.blocked_dids.sort();
    policy.blocked_dids.dedup();
    runtime.incoming_connect_policy = policy;
    runtime.incoming_connect_policy_known = true;
}

fn clear_direct_handshake_offer_events(
    runtime: &mut AgentRuntime,
    sender_member_id: Option<&str>,
    invite_code: Option<&str>,
) {
    runtime.group_events.retain(|event| {
        if event.kind != "direct_handshake_offer" {
            return true;
        }
        let sender_matches = sender_member_id
            .map(|sender| event.sender_member_id.as_deref() == Some(sender))
            .unwrap_or(false);
        let invite_matches = invite_code
            .map(|invite| event.invite_code.as_deref() == Some(invite))
            .unwrap_or(false);
        !(sender_matches || invite_matches)
    });
}

fn apply_group_event_to_runtime(runtime: &mut AgentRuntime, event: GroupMailboxRuntimeEvent) {
    match event.kind.as_str() {
        "membership_notice" => {
            if let (Some(member_id), Some(group)) = (
                event.member_id.as_ref(),
                runtime
                    .mailbox_groups
                    .iter_mut()
                    .find(|group| group.group_id == event.group_id),
            ) {
                if !group
                    .known_member_ids
                    .iter()
                    .any(|candidate| candidate == member_id)
                {
                    group.known_member_ids.push(member_id.clone());
                    group.known_member_ids.sort();
                }
            }
        }
        "group_disbanded" | "group_removed" => {
            runtime
                .mailbox_groups
                .retain(|group| group.group_id != event.group_id);
            runtime
                .pending_mailbox_groups
                .retain(|group| group.group_id != event.group_id);
            runtime.mailbox_group_revision = runtime.mailbox_group_revision.saturating_add(1);
        }
        "mailbox_rotation" | "local_kick" | "mailbox_locked" | "mailbox_unlocked" => {
            let mut updated = false;
            if let Some(group) = runtime
                .mailbox_groups
                .iter_mut()
                .find(|group| group.group_id == event.group_id)
            {
                if let Some(epoch) = event.mailbox_epoch {
                    group.mailbox_epoch = epoch;
                }
                if event.kind == "mailbox_locked" {
                    group.join_locked = true;
                } else if event.kind == "mailbox_unlocked" {
                    group.join_locked = false;
                }
                if let Some(kicked) = event.kicked_member_id.as_ref() {
                    group
                        .known_member_ids
                        .retain(|member_id| member_id != kicked);
                }
                updated = true;
            }
            if updated {
                runtime.mailbox_group_revision = runtime.mailbox_group_revision.saturating_add(1);
            }
        }
        "direct_handshake_offer_accepted"
        | "direct_handshake_offer_rejected"
        | "direct_handshake_offer_blocked" => {
            clear_direct_handshake_offer_events(
                runtime,
                event.sender_member_id.as_deref(),
                event.invite_code.as_deref(),
            );
        }
        _ => {}
    }
    push_group_event(runtime, event);
}

fn redact_group_offer_line(line: &str) -> Option<String> {
    let marker = "requested direct trust. Run /connect ";
    let idx = line.find(marker)?;
    let prefix = &line[..idx + marker.len()];
    Some(format!("{prefix}[secure-offer-code]"))
}

fn should_suppress_runtime_log(runtime: &mut AgentRuntime, line: &str) -> bool {
    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    if is_terminal_artifact_line(trimmed) {
        return true;
    }

    if runtime.suppress_group_listing_until_ms > now_ms && is_group_listing_line(trimmed) {
        return true;
    }
    if runtime.suppress_group_listing_until_ms <= now_ms {
        runtime.suppress_group_listing_until_ms = 0;
    }

    if runtime.suppress_peer_listing_until_ms > now_ms && is_peer_listing_line(trimmed) {
        return true;
    }
    if runtime.suppress_peer_listing_until_ms <= now_ms {
        runtime.suppress_peer_listing_until_ms = 0;
    }

    false
}

fn is_terminal_artifact_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed == "Headless control channel enabled"
        || trimmed == ">"
        || trimmed.starts_with("> /")
        || trimmed.ends_with(" >")
        || trimmed.starts_with("RECEIVE_DIR:")
        || trimmed.starts_with("RECEIVE_DIR_PEER:")
        || trimmed == "DIRECT_PEERS_BEGIN"
        || trimmed == "DIRECT_PEERS_END"
        || trimmed == "DIRECT_PEERS_EMPTY"
        || trimmed == "MAILBOX_GROUPS_BEGIN"
        || trimmed == "MAILBOX_GROUPS_END"
        || trimmed == "MAILBOX_GROUPS_EMPTY"
        || trimmed.starts_with("DIRECT_PEER ")
        || trimmed.starts_with("DIRECT_PEER_EVENT ")
        || trimmed.starts_with("DIRECT_MESSAGE_EVENT ")
        || trimmed.starts_with("INVITE_RESULT ")
        || trimmed.starts_with("MAILBOX_GROUP ")
        || trimmed.starts_with("HANDSHAKE_REQUEST_POLICY ")
}

fn is_peer_listing_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed == "No peers connected."
        || trimmed == "No direct peers connected."
        || trimmed == "No known direct peers yet."
        || trimmed == "Connected peers:"
        || trimmed == "Connected peers (verbose):"
        || trimmed == "Known direct peers:"
        || trimmed.starts_with("Use: /transfer ")
        || parse_peers_listing(trimmed).is_some()
        || parse_peers_verbose_header(trimmed).is_some()
}

fn is_group_listing_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed == "No active groups." || trimmed == "Active groups:" {
        return true;
    }
    if trimmed.starts_with("Local member id:")
        || trimmed.starts_with("Known members:")
        || trimmed.starts_with("Owner member id:")
        || trimmed.starts_with("Mailbox epoch:")
    {
        return true;
    }
    if trimmed
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
        && trimmed.contains(" — mailbox ")
    {
        return true;
    }
    trimmed.starts_with("- ") || trimmed.contains("(did:nxf:")
}

fn parse_incoming_chat(line: &str) -> Option<(String, String)> {
    let marker_a = "[sig verified][E2EE]";
    let marker_b = "[E2EE]";
    let marker = if line.contains(marker_a) {
        marker_a
    } else if line.contains(marker_b) {
        marker_b
    } else {
        return None;
    };
    let start = line.find(marker)?;
    let tail = line[(start + marker.len())..].trim();
    let idx = tail.find(':')?;
    if idx < 1 {
        return None;
    }
    let sender = tail[..idx].trim().to_string();
    let message = tail[(idx + 1)..].trim().to_string();
    if sender.is_empty() || message.is_empty() {
        None
    } else {
        Some((sender, message))
    }
}

fn extract_invite_token(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace())
        .find(|token| {
            token.len() >= 80
                && token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .map(|token| token.to_string())
}

fn invite_banner_matches(line: &str, kind: PendingInviteKind) -> bool {
    match kind {
        PendingInviteKind::Direct => line.contains("═══ Invite Code ═══"),
        PendingInviteKind::Group => {
            line.contains("═══ Group Invite Code ═══")
                || line.contains("═══ Group Invite ═══")
                || line.contains("═══ Ghost Group Invite ═══")
                || line.contains("═══ Anonymous Group Invite ═══")
        }
    }
}

fn invite_completion_matches(line: &str, kind: PendingInviteKind) -> bool {
    match kind {
        PendingInviteKind::Direct => {
            line.contains("Share this code with the peer you want to connect to.")
        }
        PendingInviteKind::Group => {
            line.contains("Reusable invite: multiple peers can join this group.")
                || line.contains("Group plane:")
        }
    }
}

#[cfg(test)]
fn extract_invite_from_lines<'a, I>(lines: I, kind: PendingInviteKind) -> Option<String>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut waiting_for_code = false;
    let mut previous_token: Option<String> = None;

    for raw_line in lines {
        let normalized = strip_ansi_codes(raw_line);
        let line = normalized.trim();
        if line.is_empty() {
            continue;
        }

        if invite_banner_matches(line, kind) {
            waiting_for_code = true;
            previous_token = None;
            continue;
        }

        let current_token = extract_invite_token(line);
        if waiting_for_code {
            if let Some(code) = current_token.clone() {
                return Some(code);
            }
            if line.starts_with("═══") {
                waiting_for_code = false;
            }
        }

        if invite_completion_matches(line, kind) {
            if let Some(code) = previous_token.clone() {
                return Some(code);
            }
        }

        previous_token = current_token;
    }

    None
}

#[cfg(test)]
fn extract_latest_invite_from_lines<'a, I>(lines: I, kind: PendingInviteKind) -> Option<String>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut waiting_for_code = false;
    let mut previous_token: Option<String> = None;
    let mut latest: Option<String> = None;

    for raw_line in lines {
        let normalized = strip_ansi_codes(raw_line);
        let line = normalized.trim();
        if line.is_empty() {
            continue;
        }

        if invite_banner_matches(line, kind) {
            waiting_for_code = true;
            previous_token = None;
            continue;
        }

        let current_token = extract_invite_token(line);
        if waiting_for_code {
            if let Some(code) = current_token.clone() {
                latest = Some(code);
                waiting_for_code = false;
            } else if line.starts_with("═══") {
                waiting_for_code = false;
            }
        }

        if invite_completion_matches(line, kind) {
            if let Some(code) = previous_token.clone() {
                latest = Some(code);
            }
        }

        previous_token = current_token;
    }

    latest
}

#[cfg(test)]
fn invite_error_matches(line: &str, kind: PendingInviteKind) -> bool {
    let normalized = line.strip_prefix("[stderr] ").unwrap_or(line).trim();
    if normalized.is_empty() {
        return false;
    }

    let lower = normalized.to_ascii_lowercase();
    let mentions_kind = match kind {
        PendingInviteKind::Direct => lower.contains("invite") || lower.contains("route"),
        PendingInviteKind::Group => {
            lower.contains("group")
                || lower.contains("mailbox")
                || lower.contains("invite")
                || lower.contains("owner")
        }
    };
    let looks_like_error = normalized.starts_with("Error:")
        || lower.contains("failed:")
        || lower.contains("unavailable:")
        || lower.contains("missing owner handle");

    looks_like_error && mentions_kind
}

#[cfg(test)]
fn extract_invite_error_from_lines<'a, I>(lines: I, kind: PendingInviteKind) -> Option<String>
where
    I: IntoIterator<Item = &'a String>,
{
    lines.into_iter().find_map(|raw_line| {
        let normalized = strip_ansi_codes(raw_line);
        let line = normalized
            .strip_prefix("[stderr] ")
            .unwrap_or(&normalized)
            .trim()
            .to_string();
        if invite_error_matches(&line, kind) {
            Some(line)
        } else {
            None
        }
    })
}

fn direct_invite_route_warming_up(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("invite has no route") || lower.contains("direct hidden and relay disabled")
}

fn parse_receive_dir_line(line: &str) -> Option<String> {
    if let Some(path) = line.strip_prefix("RECEIVE_DIR:") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let rest = line.strip_prefix("RECEIVE_DIR_PEER:")?;
    let (_, path) = rest.split_once(':')?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_peer_listing_status(segment: &str) -> String {
    let trimmed = segment.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("offline") {
        "offline".to_string()
    } else if lower.contains("reconnecting") {
        "reconnecting".to_string()
    } else if lower.contains("connecting") {
        "connecting".to_string()
    } else if lower.contains("online") {
        "online".to_string()
    } else if lower.contains("ready") || lower.contains("sigverify") || lower.contains("e2ee") {
        "ready".to_string()
    } else if trimmed.is_empty() {
        "ready".to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_peers_listing(line: &str) -> Option<ParsedPeerListing> {
    let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
    if indent > 3 {
        return None;
    }
    let trimmed = line.trim_start();
    let first = trimmed.chars().next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let rest = trimmed.split_once(". ")?.1;
    let did = extract_did(rest)?;
    let segments = rest
        .split(" — ")
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let name = segments
        .first()
        .copied()
        .or_else(|| rest.split(" (did:").next())
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        None
    } else {
        let status = segments
            .iter()
            .copied()
            .find(|segment| {
                let lower = segment.to_ascii_lowercase();
                lower == "online"
                    || lower == "offline"
                    || lower == "connecting"
                    || lower == "reconnecting"
            })
            .or_else(|| segments.get(2).copied())
            .map(normalize_peer_listing_status)
            .unwrap_or_else(|| "ready".to_string());
        let auto_reconnect = segments
            .iter()
            .any(|segment| segment.eq_ignore_ascii_case("paired"));
        Some(ParsedPeerListing {
            name,
            did,
            status,
            auto_reconnect,
        })
    }
}

fn extract_did(text: &str) -> Option<String> {
    let did = extract_visible_did(text)?;
    Some(normalize_peer_selector(&did))
}

fn extract_peer_id(text: &str) -> Option<String> {
    if let Some(idx) = text.find("peer_id=") {
        let tail = &text[(idx + "peer_id=".len())..];
        let token = tail
            .split(|c: char| c.is_whitespace() || c == ',' || c == ')' || c == ']' || c == '[')
            .next()
            .unwrap_or("")
            .trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    if let Some(idx) = text.find("Peer ID:") {
        let tail = &text[(idx + "Peer ID:".len())..];
        let token = tail
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| c == ')' || c == '(' || c == ',');
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    if let Some(idx) = text.find("Peer disconnected:") {
        let tail = &text[(idx + "Peer disconnected:".len())..].trim();
        let token = tail
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| c == ')' || c == '(' || c == ',');
        if token.starts_with("12D") {
            return Some(token.to_string());
        }
    }
    None
}

async fn refresh_all_runtimes(manager: &mut RuntimeManager) {
    let names: Vec<String> = manager.runtimes.keys().cloned().collect();
    for name in names {
        if let Some(runtime) = manager.runtimes.get_mut(&name) {
            refresh_child_state(runtime).await;
        }
    }
}

async fn refresh_child_state(runtime: &mut AgentRuntime) {
    let mut exited = false;
    if let Some(child) = runtime.child.as_mut() {
        match child.try_wait() {
            Ok(Some(status)) => {
                runtime.last_error = Some(format!("runtime exited with status {}", status));
                push_log(
                    runtime,
                    format!("[qypha] runtime exited with status {}", status),
                );
                exited = true;
            }
            Ok(None) => {}
            Err(e) => {
                runtime.last_error = Some(format!("runtime process check failed: {}", e));
                push_log(
                    runtime,
                    format!("[qypha] runtime process check failed: {}", e),
                );
                exited = true;
            }
        }
    }
    if exited {
        runtime.child = None;
        runtime.stdin = None;
        cleanup_transfer_event_sidechannel(runtime);
        runtime.mailbox_groups.clear();
        runtime.pending_mailbox_groups.clear();
        runtime.mailbox_group_refreshing = false;
        runtime.pending_approvals.clear();
        runtime.selected_peer = None;
        runtime.did = None;
        clear_pending_verbose_peer(runtime);
        wipe_ghost_runtime_buffers(runtime);
    }
}

fn active_runtime_mut(manager: &mut RuntimeManager) -> Result<&mut AgentRuntime, String> {
    let active = manager
        .active_agent
        .clone()
        .ok_or_else(|| "No active agent selected".to_string())?;
    manager
        .runtimes
        .get_mut(&active)
        .ok_or_else(|| format!("Active agent '{}' not found", active))
}

async fn active_runtime_command_gate(state: &RuntimeState) -> Result<Arc<Mutex<()>>, String> {
    let manager = state.inner.lock().await;
    let active = manager
        .active_agent
        .as_deref()
        .ok_or_else(|| "No active agent selected".to_string())?;
    manager
        .runtimes
        .get(active)
        .map(|runtime| runtime.command_gate.clone())
        .ok_or_else(|| format!("Active agent '{}' not found", active))
}

async fn send_line(runtime: &mut AgentRuntime, line: &str) -> Result<(), String> {
    send_line_impl(runtime, line, true).await
}

async fn send_line_silent(runtime: &mut AgentRuntime, line: &str) -> Result<(), String> {
    send_line_impl(runtime, line, false).await
}

fn encode_ui_bridge_command(command: &UiBridgeCommand) -> Result<String, String> {
    let payload = serde_json::to_vec(command)
        .map_err(|error| format!("Failed to encode UI bridge command: {}", error))?;
    Ok(format!(
        "{}{}",
        UI_BRIDGE_PREFIX,
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

fn validate_command_line(line: &str) -> Result<&str, String> {
    let clean = line.trim();
    if clean.is_empty() {
        return Err("Command is empty".to_string());
    }
    if clean.chars().any(char::is_control) {
        return Err("Command contains forbidden control characters".to_string());
    }
    Ok(clean)
}

async fn send_ui_bridge_command(
    runtime: &mut AgentRuntime,
    command: UiBridgeCommand,
) -> Result<(), String> {
    let line = encode_ui_bridge_command(&command)?;
    send_line_silent(runtime, &line).await
}

async fn send_line_impl(
    runtime: &mut AgentRuntime,
    line: &str,
    mirror_log: bool,
) -> Result<(), String> {
    refresh_child_state(runtime).await;
    let clean = validate_command_line(line)?;
    let stdin = runtime
        .stdin
        .as_mut()
        .ok_or_else(|| "Runtime is not running".to_string())?;
    stdin
        .write_all(clean.as_bytes())
        .await
        .map_err(|e| format!("stdin write failed: {}", e))?;
    stdin
        .write_all(b"\n")
        .await
        .map_err(|e| format!("stdin write failed: {}", e))?;
    stdin
        .flush()
        .await
        .map_err(|e| format!("stdin flush failed: {}", e))?;
    if mirror_log && !runtime.mode.eq_ignore_ascii_case("ghost") {
        push_log(runtime, format!("> {}", clean));
    }
    Ok(())
}

const RUNTIME_GRACEFUL_SHUTDOWN_WAIT_MS: u64 = 6_000;
const RUNTIME_GRACEFUL_SHUTDOWN_POLL_MS: u64 = 100;
const RUNTIME_FORCE_KILL_WAIT_MS: u64 = 2_000;

async fn stop_runtime_process(runtime: &mut AgentRuntime) -> Result<(), String> {
    let _ = send_line(runtime, "/quit").await;
    runtime.stdin.take();
    let mut forced_stop = false;
    if let Some(child) = runtime.child.as_mut() {
        let graceful_deadline =
            Instant::now() + Duration::from_millis(RUNTIME_GRACEFUL_SHUTDOWN_WAIT_MS);
        let mut exited_gracefully = false;
        loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(_) => {
                    exited_gracefully = true;
                    break;
                }
                None if Instant::now() >= graceful_deadline => {
                    break;
                }
                None => sleep(Duration::from_millis(RUNTIME_GRACEFUL_SHUTDOWN_POLL_MS)).await,
            }
        }
        if !exited_gracefully {
            forced_stop = true;
            let _ = child.kill().await;
            let _ = tokio::time::timeout(
                Duration::from_millis(RUNTIME_FORCE_KILL_WAIT_MS),
                child.wait(),
            )
            .await;
        }
    }
    if forced_stop {
        push_log(
            runtime,
            "[qypha] runtime graceful shutdown timed out; forcing stop".to_string(),
        );
    }
    runtime.child = None;
    cleanup_transfer_event_sidechannel(runtime);
    runtime.selected_peer = None;
    runtime.peers.clear();
    runtime.pending_peers.clear();
    runtime.peer_refreshing = false;
    runtime.mailbox_groups.clear();
    runtime.pending_mailbox_groups.clear();
    runtime.mailbox_group_refreshing = false;
    runtime.group_events.clear();
    runtime.pending_approvals.clear();
    runtime.pending_contact_requests.clear();
    runtime.did = None;
    runtime.latest_invite_error = None;
    runtime.latest_group_invite_error = None;
    clear_pending_verbose_peer(runtime);
    if runtime.mode.eq_ignore_ascii_case("ghost") {
        wipe_ghost_runtime_buffers(runtime);
    } else {
        push_log(runtime, "[qypha] runtime stopped".to_string());
    }
    Ok(())
}

async fn shutdown_all_runtimes(state: RuntimeState) {
    let mut manager = state.inner.lock().await;
    let agent_names = manager.runtimes.keys().cloned().collect::<Vec<_>>();
    for agent_name in agent_names {
        if let Some(runtime) = manager.runtimes.get_mut(&agent_name) {
            let _ = stop_runtime_process(runtime).await;
        }
    }
}

fn shutdown_all_runtimes_blocking(app: &tauri::AppHandle) {
    let state = app.state::<RuntimeState>().inner().clone();
    if state.shutdown_requested.swap(true, Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::block_on(shutdown_all_runtimes(state));
}

fn snapshot_from_runtime(runtime: &AgentRuntime, log_tail: usize) -> RuntimeSnapshot {
    let local_did = runtime.did.as_deref();
    let contact_did = read_agent_contact_did(&runtime.name);
    let mut peers: Vec<PeerSnapshot> = runtime
        .peers
        .values()
        .cloned()
        .filter(|p| local_did != Some(p.did.as_str()))
        .map(|p| PeerSnapshot {
            name: p.name,
            did: p.did,
            contact_did: p.contact_did,
            status: p.status,
            auto_reconnect: p.auto_reconnect,
        })
        .collect();
    peers.sort_by(|a, b| a.name.cmp(&b.name));

    let mut pending_contact_requests = runtime
        .pending_contact_requests
        .values()
        .cloned()
        .map(|request| PendingContactRequestSnapshot {
            name: request.name,
            did: request
                .contact_did
                .clone()
                .unwrap_or_else(|| request.did.clone()),
            contact_did: request.contact_did,
            canonical_did: Some(request.did),
            ts_ms: request.ts_ms,
        })
        .collect::<Vec<_>>();
    pending_contact_requests.sort_by(|a, b| b.ts_ms.cmp(&a.ts_ms));

    let logs_len = runtime.logs.len();
    let start = logs_len.saturating_sub(log_tail);
    let recent_logs = runtime.logs.iter().skip(start).cloned().collect::<Vec<_>>();
    let transfer_events = runtime.transfer_events.iter().cloned().collect::<Vec<_>>();
    let direct_events = runtime.direct_events.iter().cloned().collect::<Vec<_>>();
    let peer_events = runtime.peer_events.iter().cloned().collect::<Vec<_>>();
    let mut ghost_handoffs = runtime
        .ghost_handoffs
        .values()
        .cloned()
        .map(|handoff| {
            let contact_did = runtime
                .peers
                .get(&handoff.peer_did)
                .and_then(|peer| peer.contact_did.clone())
                .or_else(|| contact_did_from_canonical_did(&handoff.peer_did));
            GhostHandoffSnapshot {
                handoff_id: handoff.handoff_id,
                peer_did: contact_did
                    .clone()
                    .unwrap_or_else(|| handoff.peer_did.clone()),
                peer_contact_did: contact_did,
                peer_canonical_did: Some(handoff.peer_did),
                peer_name: handoff.peer_name,
                filename: handoff.filename,
                created_at_ms: handoff.created_at_ms,
            }
        })
        .collect::<Vec<_>>();
    ghost_handoffs.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms));

    RuntimeSnapshot {
        running: runtime.child.is_some(),
        pid: runtime.child.as_ref().and_then(Child::id),
        started_at: runtime.started_at.clone(),
        contact_did,
        selected_peer: runtime.selected_peer.clone(),
        last_error: runtime.last_error.clone(),
        mode: runtime.mode.clone(),
        transport: runtime.transport.clone(),
        listen_port: runtime.listen_port,
        peers,
        mailbox_groups: runtime.mailbox_groups.clone(),
        pending_approvals: runtime.pending_approvals.clone(),
        pending_contact_requests,
        recent_logs,
        transfer_events,
        direct_events,
        peer_events,
        group_events: runtime.group_events.iter().cloned().collect(),
        handshake_request_policy: runtime.handshake_request_policy.clone(),
        incoming_connect_policy: runtime.incoming_connect_policy.clone(),
        latest_invite_code: runtime.latest_invite_code.clone(),
        latest_invite_revision: runtime.latest_invite_revision,
        latest_group_invite_code: runtime.latest_group_invite_code.clone(),
        latest_group_invite_revision: runtime.latest_group_invite_revision,
        receive_dir: runtime.receive_dir.clone(),
        ghost_handoffs,
    }
}

fn main() {
    tauri::Builder::default()
        .manage(RuntimeState::default())
        .invoke_handler(tauri::generate_handler![
            app_security_profile,
            list_ai_provider_catalog,
            get_ai_provider_secret_status,
            set_ai_provider_secret,
            delete_ai_provider_secret,
            list_agent_skills,
            save_agent_skill,
            delete_agent_skill,
            agent_init,
            load_ai_agent_thread,
            ai_agent_send_message,
            runtime_select_agent,
            runtime_start,
            runtime_stop,
            runtime_destroy_agent,
            runtime_destroy_all_agents,
            runtime_snapshot,
            runtime_refresh_peers,
            runtime_refresh_groups,
            runtime_list_peers,
            runtime_try_list_peers,
            runtime_list_groups,
            runtime_try_list_groups,
            runtime_invite,
            runtime_invite_group,
            runtime_regenerate_group_invite,
            runtime_accept_group_handshake_offer,
            runtime_reject_group_handshake_offer,
            runtime_block_group_handshake_offer,
            runtime_set_incoming_connect_block,
            runtime_set_incoming_connect_block_all,
            runtime_accept_group_file_offer,
            runtime_reject_group_file_offer,
            runtime_set_selected_peer,
            runtime_send_message,
            runtime_send_console_input,
            runtime_send_group_message,
            runtime_sendto,
            runtime_connect_invite,
            runtime_connect_did,
            runtime_disconnect_peer,
            runtime_forget_peer_history,
            runtime_send_group_handshake_invite,
            runtime_set_handshake_request_block,
            runtime_set_handshake_request_block_all,
            runtime_kick_group_member,
            runtime_set_group_join_lock,
            runtime_leave_group,
            runtime_disband_group,
            runtime_transfer,
            runtime_transfer_group,
            pick_transfer_path,
            pick_transfer_file,
            pick_transfer_folder,
            runtime_accept,
            runtime_reject,
            runtime_accept_always,
            runtime_accept_ask,
            get_workspace_root,
            set_receive_dir,
            get_receive_dir,
            runtime_export_handoff,
            runtime_discard_handoff
        ])
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                shutdown_all_runtimes_blocking(&window.app_handle());
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build Qypha desktop app")
        .run(|app, event| {
            if matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                shutdown_all_runtimes_blocking(app);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ghost_runtime() -> AgentRuntime {
        AgentRuntime {
            name: "ghost".to_string(),
            mode: "ghost".to_string(),
            transport: "tor".to_string(),
            listen_port: 9090,
            ..Default::default()
        }
    }

    #[test]
    fn validate_command_line_rejects_control_characters() {
        let error = validate_command_line("/sendto did:nxf:alice hello\n/quit").unwrap_err();
        assert!(error.contains("forbidden control characters"));
    }

    #[test]
    fn ui_bridge_encoding_stays_single_line() {
        let line = encode_ui_bridge_command(&UiBridgeCommand::SendTo {
            selector: "did:nxf:alice".to_string(),
            message: "hello via bridge".to_string(),
        })
        .unwrap();

        assert!(line.starts_with(UI_BRIDGE_PREFIX));
        assert!(!line.chars().any(char::is_control));
    }

    #[test]
    fn ghost_runtime_does_not_persist_raw_chat_logs() {
        let mut runtime = ghost_runtime();
        let events = ingest_runtime_line(
            &mut runtime,
            "[sig verified][E2EE] Alice: hello from ghost".to_string(),
        );

        assert!(runtime.logs.is_empty());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "incoming_chat");
        assert_eq!(events[0].sender.as_deref(), Some("Alice"));
        assert_eq!(events[0].message.as_deref(), Some("hello from ghost"));
    }

    #[test]
    fn ghost_runtime_tracks_invites_and_receive_dir_without_logs() {
        let mut runtime = ghost_runtime();
        let direct_token = "A".repeat(96);
        let group_token = "B".repeat(96);

        let direct_banner = ingest_runtime_line(&mut runtime, "═══ Invite Code ═══".to_string());
        assert!(direct_banner.is_empty());
        let direct_events = ingest_runtime_line(&mut runtime, direct_token.clone());
        assert!(runtime.logs.is_empty());
        assert_eq!(
            runtime.latest_invite_code.as_deref(),
            Some(direct_token.as_str())
        );
        assert_eq!(runtime.latest_invite_revision, 1);
        assert_eq!(direct_events.len(), 1);
        assert_eq!(direct_events[0].kind.as_deref(), Some("direct"));
        assert_eq!(direct_events[0].revision, Some(1));

        let group_banner =
            ingest_runtime_line(&mut runtime, "═══ Group Invite Code ═══".to_string());
        assert!(group_banner.is_empty());
        let group_events = ingest_runtime_line(&mut runtime, group_token.clone());
        assert_eq!(
            runtime.latest_group_invite_code.as_deref(),
            Some(group_token.as_str())
        );
        assert_eq!(runtime.latest_group_invite_revision, 1);
        assert_eq!(group_events.len(), 1);
        assert_eq!(group_events[0].kind.as_deref(), Some("group"));
        assert_eq!(group_events[0].revision, Some(1));

        let receive_events = ingest_runtime_line(
            &mut runtime,
            "RECEIVE_DIR:/Users/test/Desktop/received".to_string(),
        );
        assert!(receive_events.is_empty());
        assert_eq!(
            runtime.receive_dir.as_deref(),
            Some("/Users/test/Desktop/received")
        );
        assert!(runtime.logs.is_empty());
    }

    #[test]
    fn ghost_group_invite_banner_updates_group_revision() {
        let mut runtime = ghost_runtime();
        let group_token = "G".repeat(96);

        let banner_events =
            ingest_runtime_line(&mut runtime, "═══ Ghost Group Invite ═══".to_string());
        assert!(banner_events.is_empty());

        let group_events = ingest_runtime_line(&mut runtime, group_token.clone());
        assert_eq!(
            runtime.latest_group_invite_code.as_deref(),
            Some(group_token.as_str())
        );
        assert_eq!(runtime.latest_group_invite_revision, 1);
        assert_eq!(group_events.len(), 1);
        assert_eq!(group_events[0].kind.as_deref(), Some("group"));
    }

    #[test]
    fn desktop_listen_port_availability_requires_udp_and_tcp() {
        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind udp");
        let port = udp.local_addr().expect("udp addr").port();

        assert!(
            !is_desktop_listen_port_available(port),
            "udp occupancy must mark desktop listen port unavailable"
        );
    }

    #[test]
    fn desktop_listen_port_guard_rejects_busy_or_zero_ports() {
        assert!(ensure_desktop_listen_port_available(0).is_err());

        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind udp");
        let port = udp.local_addr().expect("udp addr").port();

        assert!(ensure_desktop_listen_port_available(port).is_err());
    }

    #[test]
    fn runtime_tracks_invites_when_command_sets_pending_kind_without_banner() {
        let mut runtime = AgentRuntime::default();
        let direct_token = "A".repeat(96);
        let group_token = "B".repeat(96);

        runtime.pending_invite_kind = Some(PendingInviteKind::Direct);
        let direct_events = ingest_runtime_line(&mut runtime, direct_token.clone());
        assert_eq!(
            runtime.latest_invite_code.as_deref(),
            Some(direct_token.as_str())
        );
        assert_eq!(runtime.latest_invite_revision, 1);
        assert_eq!(direct_events.len(), 1);
        assert_eq!(direct_events[0].kind.as_deref(), Some("direct"));
        assert_eq!(direct_events[0].revision, Some(1));
        assert!(runtime.pending_invite_kind.is_none());

        runtime.pending_invite_kind = Some(PendingInviteKind::Group);
        let group_events = ingest_runtime_line(&mut runtime, group_token.clone());
        assert_eq!(
            runtime.latest_group_invite_code.as_deref(),
            Some(group_token.as_str())
        );
        assert_eq!(runtime.latest_group_invite_revision, 1);
        assert_eq!(group_events.len(), 1);
        assert_eq!(group_events[0].kind.as_deref(), Some("group"));
        assert_eq!(group_events[0].revision, Some(1));
        assert!(runtime.pending_invite_kind.is_none());
    }

    #[test]
    fn runtime_invite_revision_advances_even_when_code_shape_repeats() {
        let mut runtime = AgentRuntime::default();
        let token = "A".repeat(96);

        runtime.pending_invite_kind = Some(PendingInviteKind::Direct);
        ingest_runtime_line(&mut runtime, token.clone());
        assert_eq!(runtime.latest_invite_revision, 1);

        runtime.pending_invite_kind = Some(PendingInviteKind::Direct);
        ingest_runtime_line(&mut runtime, token);
        assert_eq!(runtime.latest_invite_revision, 2);
    }

    #[test]
    fn runtime_ingests_headless_group_invite_result_and_upserts_group() {
        let mut runtime = AgentRuntime::default();
        let token = "G".repeat(96);
        let line = format!(
            "INVITE_RESULT {{\"kind\":\"group\",\"code\":\"{token}\",\"error\":null,\"group\":{{\"group_id\":\"grp_test\",\"group_name\":\"ops\",\"anonymous_group\":false,\"persistence\":\"encrypted_disk\",\"local_member_id\":\"did:nxf:self\",\"owner_member_id\":\"did:nxf:self\",\"owner_special_id\":null,\"known_member_ids\":[\"did:nxf:self\"],\"mailbox_epoch\":0,\"join_locked\":false,\"degraded\":false}}}}"
        );

        let events = ingest_runtime_line(&mut runtime, line);

        assert_eq!(
            runtime.latest_group_invite_code.as_deref(),
            Some(token.as_str())
        );
        assert_eq!(runtime.latest_group_invite_revision, 1);
        assert_eq!(runtime.mailbox_groups.len(), 1);
        assert_eq!(runtime.mailbox_groups[0].group_id, "grp_test");
        assert_eq!(runtime.mailbox_group_revision, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.as_deref(), Some("group"));
    }

    #[test]
    fn runtime_replaces_direct_peer_snapshot_from_headless_markers() {
        let mut runtime = AgentRuntime::default();

        ingest_runtime_line(&mut runtime, "DIRECT_PEERS_BEGIN".to_string());
        ingest_runtime_line(
            &mut runtime,
            "DIRECT_PEER {\"name\":\"agent2\",\"did\":\"did:nxf:peer2\",\"peer_id\":\"12D3KooPeer2\",\"status\":\"ready\"}".to_string(),
        );
        ingest_runtime_line(
            &mut runtime,
            "DIRECT_PEER {\"name\":\"agent3\",\"did\":\"did:nxf:peer3\",\"peer_id\":\"12D3KooPeer3\",\"status\":\"connecting\"}".to_string(),
        );
        let events = ingest_runtime_line(&mut runtime, "DIRECT_PEERS_END".to_string());

        assert!(events.is_empty());
        assert_eq!(runtime.peer_revision, 1);
        assert_eq!(runtime.peers.len(), 2);
        assert_eq!(
            runtime
                .peers
                .get("did:nxf:peer2")
                .map(|peer| peer.status.as_str()),
            Some("ready")
        );
        assert_eq!(
            runtime
                .peers
                .get("did:nxf:peer3")
                .map(|peer| peer.status.as_str()),
            Some("connecting")
        );
    }

    #[test]
    fn runtime_ingests_structured_direct_message_event() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let line = format!(
            "DIRECT_MESSAGE_EVENT {{\"direction\":\"incoming\",\"peer_did\":\"{}\",\"peer_name\":\"Alice\",\"message\":\"hello structured\",\"ts_ms\":1731234567890}}",
            did
        );

        let events = ingest_runtime_line(&mut runtime, line);

        assert!(events.is_empty());
        assert_eq!(runtime.direct_events.len(), 1);
        assert_eq!(
            runtime.direct_events[0].peer_did,
            contact_did_from_canonical_did(did).unwrap()
        );
        assert_eq!(
            runtime.direct_events[0].peer_canonical_did.as_deref(),
            Some(did)
        );
        assert_eq!(runtime.direct_events[0].message, "hello structured");
        let peer = runtime
            .peers
            .get(did)
            .expect("expected peer to hydrate from message");
        assert_eq!(peer.name, "Alice");
        assert_eq!(peer.status, "ready");
        assert_eq!(
            peer.contact_did.as_deref(),
            contact_did_from_canonical_did(did).as_deref()
        );
        assert!(peer.auto_reconnect);
        assert!(runtime.logs.is_empty());
    }

    #[test]
    fn runtime_ingests_structured_peer_lifecycle_events() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";

        let connected = ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"connected\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"12D3KooAlice\",\"status\":\"ready\",\"reason\":null,\"ts_ms\":1731234567890}}",
                did
            ),
        );
        assert!(connected.is_empty());
        assert_eq!(runtime.peers.len(), 1);
        assert_eq!(
            runtime.peers.get(did).map(|peer| peer.status.as_str()),
            Some("ready")
        );
        assert_eq!(
            runtime
                .peer_events
                .front()
                .and_then(|event| event.contact_did.as_deref()),
            contact_did_from_canonical_did(did).as_deref()
        );

        let reconnecting = ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"reconnecting\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"12D3KooAlice\",\"status\":\"reconnecting\",\"reason\":\"auto_reconnect\",\"ts_ms\":1731234567999}}",
                did
            ),
        );
        assert!(reconnecting.is_empty());
        assert_eq!(
            runtime.peers.get(did).map(|peer| peer.status.as_str()),
            Some("reconnecting")
        );

        let disconnected = ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"disconnected\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"12D3KooAlice\",\"status\":\"offline\",\"reason\":\"manual_disconnect\",\"ts_ms\":1731234568999}}",
                did
            ),
        );
        assert!(disconnected.is_empty());
        assert!(runtime.peers.is_empty());
        assert_eq!(runtime.peer_events.len(), 3);
    }

    #[test]
    fn stale_connection_closed_log_does_not_drop_reconnecting_peer() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
        let peer_id = "12D3KooAlice";

        ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"connected\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"{}\",\"status\":\"ready\",\"reason\":null,\"ts_ms\":1731234567890}}",
                did, peer_id
            ),
        );
        ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"reconnecting\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"{}\",\"status\":\"reconnecting\",\"reason\":\"auto_reconnect\",\"ts_ms\":1731234567999}}",
                did, peer_id
            ),
        );

        let events = ingest_runtime_line(
            &mut runtime,
            format!("[stderr] Connection closed peer_id={peer_id}"),
        );

        assert!(events.is_empty());
        assert_eq!(
            runtime.peers.get(did).map(|peer| peer.status.as_str()),
            Some("reconnecting")
        );
    }

    #[test]
    fn stale_peer_disconnected_log_does_not_drop_reconnecting_peer() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
        let peer_id = "12D3KooAlice";

        ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"connected\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"{}\",\"status\":\"ready\",\"reason\":null,\"ts_ms\":1731234567890}}",
                did, peer_id
            ),
        );
        ingest_runtime_line(
            &mut runtime,
            format!(
                "DIRECT_PEER_EVENT {{\"event\":\"reconnecting\",\"did\":\"{}\",\"name\":\"Alice\",\"peer_id\":\"{}\",\"status\":\"reconnecting\",\"reason\":\"auto_reconnect\",\"ts_ms\":1731234567999}}",
                did, peer_id
            ),
        );

        let events = ingest_runtime_line(
            &mut runtime,
            format!("[stderr] Peer disconnected: {peer_id}"),
        );

        assert!(events.is_empty());
        assert_eq!(
            runtime.peers.get(did).map(|peer| peer.status.as_str()),
            Some("reconnecting")
        );
    }

    #[test]
    fn peer_refresh_empty_preserves_reconnecting_placeholder() {
        let mut runtime = AgentRuntime::default();
        runtime.peers.insert(
            "did:nxf:alice".to_string(),
            PeerRuntime {
                name: "Alice".to_string(),
                did: "did:nxf:alice".to_string(),
                contact_did: None,
                peer_id: Some("12D3KooAlice".to_string()),
                status: "reconnecting".to_string(),
                auto_reconnect: true,
            },
        );
        runtime.selected_peer = Some("did:nxf:alice".to_string());

        let events = ingest_runtime_line(&mut runtime, "DIRECT_PEERS_EMPTY".to_string());

        assert!(events.is_empty());
        assert_eq!(runtime.peers.len(), 1);
        assert_eq!(
            runtime
                .peers
                .get("did:nxf:alice")
                .map(|peer| peer.status.as_str()),
            Some("reconnecting")
        );
        assert_eq!(runtime.selected_peer.as_deref(), Some("did:nxf:alice"));
    }

    #[test]
    fn peer_refresh_merge_keeps_reconnecting_peer_when_listing_is_partial() {
        let mut runtime = AgentRuntime::default();
        runtime.peers.insert(
            "did:nxf:alice".to_string(),
            PeerRuntime {
                name: "Alice".to_string(),
                did: "did:nxf:alice".to_string(),
                contact_did: None,
                peer_id: Some("12D3KooAlice".to_string()),
                status: "reconnecting".to_string(),
                auto_reconnect: true,
            },
        );
        runtime.pending_peers.push(PeerRuntime {
            name: "Bob".to_string(),
            did: "did:nxf:bob".to_string(),
            contact_did: None,
            peer_id: Some("12D3KooBob".to_string()),
            status: "ready".to_string(),
            auto_reconnect: false,
        });

        apply_pending_peer_refresh(&mut runtime);

        assert_eq!(runtime.peers.len(), 2);
        assert_eq!(
            runtime
                .peers
                .get("did:nxf:alice")
                .map(|peer| peer.status.as_str()),
            Some("reconnecting")
        );
        assert_eq!(
            runtime
                .peers
                .get("did:nxf:bob")
                .map(|peer| peer.status.as_str()),
            Some("ready")
        );
    }

    #[test]
    fn direct_peer_event_disconnect_keeps_known_peer_as_offline() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:alice";
        runtime.peers.insert(
            did.to_string(),
            PeerRuntime {
                name: "Alice".to_string(),
                did: did.to_string(),
                contact_did: None,
                peer_id: Some("12D3KooAlice".to_string()),
                status: "ready".to_string(),
                auto_reconnect: true,
            },
        );

        apply_direct_peer_event_to_runtime(
            &mut runtime,
            DirectPeerRuntimeEvent {
                event: "disconnected".to_string(),
                did: did.to_string(),
                contact_did: None,
                canonical_did: None,
                name: "Alice".to_string(),
                peer_id: Some("12D3KooAlice".to_string()),
                status: "offline".to_string(),
                reason: Some("connection_lost".to_string()),
                ts_ms: 1,
            },
        );

        let peer = runtime
            .peers
            .get(did)
            .expect("expected peer to remain known");
        assert_eq!(peer.status, "offline");
        assert!(peer.auto_reconnect);
    }

    #[test]
    fn direct_peer_event_manual_disconnect_removes_peer() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:alice";
        runtime.peers.insert(
            did.to_string(),
            PeerRuntime {
                name: "Alice".to_string(),
                did: did.to_string(),
                contact_did: None,
                peer_id: Some("12D3KooAlice".to_string()),
                status: "ready".to_string(),
                auto_reconnect: true,
            },
        );

        apply_direct_peer_event_to_runtime(
            &mut runtime,
            DirectPeerRuntimeEvent {
                event: "disconnected".to_string(),
                did: did.to_string(),
                contact_did: None,
                canonical_did: None,
                name: "Alice".to_string(),
                peer_id: Some("12D3KooAlice".to_string()),
                status: "offline".to_string(),
                reason: Some("manual_disconnect".to_string()),
                ts_ms: 1,
            },
        );

        assert!(!runtime.peers.contains_key(did));
    }

    #[test]
    fn anonymous_disconnect_line_keeps_single_known_peer_as_offline() {
        let mut runtime = AgentRuntime::default();
        runtime.peers.insert(
            "did:nxf:alice".to_string(),
            PeerRuntime {
                name: "Alice".to_string(),
                did: "did:nxf:alice".to_string(),
                contact_did: None,
                peer_id: None,
                status: "ready".to_string(),
                auto_reconnect: true,
            },
        );

        let events = ingest_runtime_line(&mut runtime, "Peer disconnected:".to_string());

        assert!(events.is_empty());
        assert_eq!(
            runtime
                .peers
                .get("did:nxf:alice")
                .map(|peer| peer.status.as_str()),
            Some("offline")
        );
    }

    #[test]
    fn extract_invite_from_logs_finds_group_code_after_group_plane_note() {
        let group_token = "C".repeat(96);
        let lines = vec![
            "═══ Group Invite ═══".to_string(),
            "Group: group1".to_string(),
            group_token.clone(),
            "Group plane: mailbox session is identified, Tor-backed, and does not create any peer route.".to_string(),
        ];

        let extracted = extract_invite_from_lines(lines.iter(), PendingInviteKind::Group);

        assert_eq!(extracted.as_deref(), Some(group_token.as_str()));
    }

    #[test]
    fn extract_latest_invite_from_logs_returns_most_recent_direct_code() {
        let first_token = "D".repeat(96);
        let second_token = "E".repeat(96);
        let lines = vec![
            "═══ Invite Code ═══".to_string(),
            first_token.clone(),
            "Share this code with the peer you want to connect to.".to_string(),
            "═══ Invite Code ═══".to_string(),
            second_token.clone(),
            "Share this code with the peer you want to connect to.".to_string(),
        ];

        let extracted = extract_latest_invite_from_lines(lines.iter(), PendingInviteKind::Direct);

        assert_eq!(extracted.as_deref(), Some(second_token.as_str()));
    }

    #[test]
    fn extract_invite_error_from_logs_returns_direct_route_failure() {
        let lines = vec![
            "═══ Invite Code ═══".to_string(),
            "Error: iroh invite has no route (direct hidden and relay disabled)".to_string(),
        ];

        let extracted = extract_invite_error_from_lines(lines.iter(), PendingInviteKind::Direct);

        assert_eq!(
            extracted.as_deref(),
            Some("Error: iroh invite has no route (direct hidden and relay disabled)")
        );
    }

    #[test]
    fn extract_invite_error_from_logs_returns_group_failure() {
        let lines = vec![
            "Mailbox provisioning failed: relay unavailable".to_string(),
            "Group create failed: invite not issued".to_string(),
        ];

        let extracted = extract_invite_error_from_lines(lines.iter(), PendingInviteKind::Group);

        assert_eq!(
            extracted.as_deref(),
            Some("Mailbox provisioning failed: relay unavailable")
        );
    }

    #[test]
    fn detects_transient_direct_invite_route_warmup_error() {
        assert!(direct_invite_route_warming_up(
            "Error: iroh invite has no route (direct hidden and relay disabled)"
        ));
        assert!(!direct_invite_route_warming_up(
            "Error: peer selector is ambiguous"
        ));
    }

    #[test]
    fn runtime_preserves_group_event_timestamp_from_backend() {
        let mut runtime = AgentRuntime::default();
        let ts_ms = 1_731_234_567_890_i64;
        let line = format!(
            "GROUP_MAILBOX_EVENT {{\"kind\":\"chat\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:test\",\"message\":\"hello\",\"filename\":null,\"size_bytes\":null,\"member_id\":null,\"member_display_name\":\"agent2\",\"invite_code\":null,\"mailbox_epoch\":3,\"kicked_member_id\":null,\"ts_ms\":{ts_ms}}}"
        );

        let events = ingest_runtime_line(&mut runtime, line);

        assert!(events.is_empty());
        assert_eq!(runtime.group_events.len(), 1);
        assert_eq!(runtime.group_events[0].kind, "chat");
        assert_eq!(runtime.group_events[0].ts_ms, ts_ms);
    }

    #[test]
    fn runtime_parses_group_event_even_when_prompt_text_prefixes_line() {
        let mut runtime = AgentRuntime::default();
        let line = "agent3[group_test] > GROUP_MAILBOX_EVENT {\"kind\":\"chat\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:test\",\"message\":\"hello again\",\"filename\":null,\"size_bytes\":null,\"member_id\":null,\"member_display_name\":\"agent4\",\"invite_code\":null,\"mailbox_epoch\":3,\"kicked_member_id\":null,\"ts_ms\":1731234567890}".to_string();

        let events = ingest_runtime_line(&mut runtime, line);

        assert!(events.is_empty());
        assert_eq!(runtime.group_events.len(), 1);
        assert_eq!(
            runtime.group_events[0].message.as_deref(),
            Some("hello again")
        );
        assert_eq!(
            runtime.group_events[0].member_display_name.as_deref(),
            Some("agent4")
        );
    }

    #[test]
    fn runtime_does_not_parse_group_member_roster_lines_as_direct_peers() {
        let mut runtime = AgentRuntime::default();

        let events = ingest_runtime_line(
            &mut runtime,
            "        1. agent2 (did:nxf:1234abcd5678ef90)".to_string(),
        );

        assert!(events.is_empty());
        assert!(runtime.peers.is_empty());
    }

    #[test]
    fn runtime_parses_known_peer_roster_lines_as_offline_paired_peers() {
        let mut runtime = AgentRuntime::default();
        let canonical = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        let contact = contact_did_from_canonical_did(canonical).expect("contact did");

        let events = ingest_runtime_line(
            &mut runtime,
            format!("   1. agent2 — {contact} — offline — paired"),
        );

        assert!(events.is_empty());
        let peer = runtime
            .peers
            .get(canonical)
            .expect("expected offline peer from /all roster");
        assert_eq!(peer.name, "agent2");
        assert_eq!(peer.status, "offline");
        assert!(peer.auto_reconnect);
    }

    #[test]
    fn runtime_records_local_identity_without_creating_self_peer() {
        let mut runtime = AgentRuntime::default();

        let events = ingest_runtime_line(
            &mut runtime,
            "   DID:       did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b"
                .to_string(),
        );

        assert!(events.is_empty());
        assert_eq!(
            runtime.did.as_deref(),
            Some("did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b")
        );
        assert!(runtime.peers.is_empty());

        let events = ingest_runtime_line(
            &mut runtime,
            "   Peer ID:   12D3KooWRYDoFnBT9arzxRt1LjDEEKi86tkrwfe4LCb2BCpkkvqa".to_string(),
        );

        assert!(events.is_empty());
        assert!(runtime.peers.is_empty());
    }

    #[test]
    fn extract_did_normalizes_visible_contact_did_to_canonical() {
        let canonical = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        let contact = contact_did_from_canonical_did(canonical).expect("contact did");

        assert_eq!(
            extract_did(&format!("Peer connected: alice ({contact})")).as_deref(),
            Some(canonical)
        );
    }

    #[test]
    fn runtime_updates_auto_reconnect_flag_from_canonical_toggle_line() {
        let mut runtime = AgentRuntime::default();
        let did = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        runtime.peers.insert(
            did.to_string(),
            PeerRuntime {
                name: "alice".to_string(),
                did: did.to_string(),
                contact_did: contact_did_from_canonical_did(did),
                peer_id: Some("12D3KooAlice".to_string()),
                status: "connected".to_string(),
                auto_reconnect: false,
            },
        );

        let events = ingest_runtime_line(&mut runtime, format!("AUTO_RECONNECT_SET:{did}:true"));

        assert!(events.is_empty());
        assert_eq!(
            runtime.peers.get(did).map(|peer| peer.auto_reconnect),
            Some(true)
        );
    }

    #[test]
    fn runtime_log_rewrites_canonical_dids_to_visible_contact_dids() {
        let canonical = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        let contact = contact_did_from_canonical_did(canonical).expect("contact did");

        let line = format!("AUTO_RECONNECT_SET:{canonical}:true");
        assert_eq!(
            rewrite_runtime_log_dids_for_display(&line),
            format!("AUTO_RECONNECT_SET:{contact}:true")
        );
    }

    #[test]
    fn snapshot_excludes_local_agent_from_peer_list() {
        let mut runtime = AgentRuntime::default();
        runtime.did = Some("did:nxf:self".to_string());
        runtime.peers.insert(
            "did:nxf:self".to_string(),
            PeerRuntime {
                name: "agent4".to_string(),
                did: "did:nxf:self".to_string(),
                contact_did: None,
                peer_id: Some("12D3KooSelf".to_string()),
                status: "connected".to_string(),
                auto_reconnect: false,
            },
        );
        runtime.peers.insert(
            "did:nxf:remote".to_string(),
            PeerRuntime {
                name: "agent2".to_string(),
                did: "did:nxf:remote".to_string(),
                contact_did: None,
                peer_id: Some("12D3KooRemote".to_string()),
                status: "connected".to_string(),
                auto_reconnect: true,
            },
        );

        let snapshot = snapshot_from_runtime(&runtime, 64);

        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].did, "did:nxf:remote");
    }

    #[test]
    fn runtime_tracks_handshake_request_policy_and_prunes_blocked_offers() {
        let mut runtime = AgentRuntime::default();
        ingest_runtime_line(
            &mut runtime,
            "GROUP_MAILBOX_EVENT {\"kind\":\"direct_handshake_offer\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:blocked\",\"message\":null,\"filename\":null,\"size_bytes\":null,\"member_id\":null,\"member_display_name\":null,\"invite_code\":\"invite-code\",\"mailbox_epoch\":1,\"kicked_member_id\":null,\"ts_ms\":1731234567890}".to_string(),
        );
        assert_eq!(runtime.group_events.len(), 1);

        let events = ingest_runtime_line(
            &mut runtime,
            "HANDSHAKE_REQUEST_POLICY {\"block_all\":false,\"blocked_member_ids\":[\"did:nxf:blocked\"]}".to_string(),
        );

        assert!(events.is_empty());
        assert_eq!(runtime.handshake_request_policy.blocked_member_ids.len(), 1);
        assert!(runtime.group_events.is_empty());
    }

    #[test]
    fn runtime_prunes_pending_handshake_offer_when_offer_is_handled() {
        let mut runtime = AgentRuntime::default();
        ingest_runtime_line(
            &mut runtime,
            "GROUP_MAILBOX_EVENT {\"kind\":\"direct_handshake_offer\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:alice\",\"message\":null,\"filename\":null,\"size_bytes\":null,\"member_id\":null,\"member_display_name\":null,\"invite_code\":\"invite-code\",\"mailbox_epoch\":1,\"kicked_member_id\":null,\"ts_ms\":1731234567890}".to_string(),
        );
        assert_eq!(runtime.group_events.len(), 1);

        let events = ingest_runtime_line(
            &mut runtime,
            "GROUP_MAILBOX_EVENT {\"kind\":\"direct_handshake_offer_accepted\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:alice\",\"message\":\"accepted via secure direct-connect flow\",\"filename\":null,\"size_bytes\":null,\"member_id\":null,\"member_display_name\":null,\"invite_code\":null,\"mailbox_epoch\":null,\"kicked_member_id\":null,\"ts_ms\":1731234567999}".to_string(),
        );

        assert!(events.is_empty());
        assert_eq!(runtime.group_events.len(), 1);
        assert_eq!(
            runtime.group_events[0].kind,
            "direct_handshake_offer_accepted"
        );
    }

    #[test]
    fn runtime_removes_mailbox_group_when_group_removed_event_arrives() {
        let mut runtime = AgentRuntime::default();
        runtime.mailbox_groups.push(MailboxGroupSnapshot {
            group_id: "grp_test".to_string(),
            group_name: Some("g1".to_string()),
            anonymous_group: false,
            persistence: "encrypted_disk".to_string(),
            local_member_id: Some("did:nxf:member".to_string()),
            owner_member_id: Some("did:nxf:owner".to_string()),
            owner_special_id: None,
            known_member_ids: vec!["did:nxf:member".to_string()],
            mailbox_epoch: 2,
            join_locked: false,
            degraded: false,
        });

        let events = ingest_runtime_line(
            &mut runtime,
            "GROUP_MAILBOX_EVENT {\"kind\":\"group_removed\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:owner\",\"message\":\"removed from group by owner\",\"filename\":null,\"size_bytes\":null,\"member_id\":\"did:nxf:member\",\"member_display_name\":null,\"invite_code\":null,\"mailbox_epoch\":3,\"kicked_member_id\":\"did:nxf:member\",\"ts_ms\":1731234567999}".to_string(),
        );

        assert!(events.is_empty());
        assert!(runtime.mailbox_groups.is_empty());
        assert_eq!(runtime.group_events.len(), 1);
        assert_eq!(runtime.group_events[0].kind, "group_removed");
    }

    #[test]
    fn runtime_updates_join_lock_when_mailbox_lock_event_arrives() {
        let mut runtime = AgentRuntime::default();
        runtime.mailbox_groups.push(MailboxGroupSnapshot {
            group_id: "grp_test".to_string(),
            group_name: Some("g1".to_string()),
            anonymous_group: false,
            persistence: "encrypted_disk".to_string(),
            local_member_id: Some("did:nxf:owner".to_string()),
            owner_member_id: Some("did:nxf:owner".to_string()),
            owner_special_id: None,
            known_member_ids: vec!["did:nxf:owner".to_string()],
            mailbox_epoch: 0,
            join_locked: false,
            degraded: false,
        });

        let events = ingest_runtime_line(
            &mut runtime,
            "GROUP_MAILBOX_EVENT {\"kind\":\"mailbox_locked\",\"group_id\":\"grp_test\",\"group_name\":\"g1\",\"anonymous_group\":false,\"manifest_id\":null,\"sender_member_id\":\"did:nxf:owner\",\"message\":\"group locked by owner\",\"filename\":null,\"size_bytes\":null,\"member_id\":null,\"member_display_name\":null,\"invite_code\":null,\"mailbox_epoch\":1,\"kicked_member_id\":null,\"ts_ms\":1731234567999}".to_string(),
        );

        assert!(events.is_empty());
        assert_eq!(runtime.mailbox_groups.len(), 1);
        assert!(runtime.mailbox_groups[0].join_locked);
        assert_eq!(runtime.mailbox_groups[0].mailbox_epoch, 1);
        assert_eq!(runtime.group_events.len(), 1);
        assert_eq!(runtime.group_events[0].kind, "mailbox_locked");
    }

    #[test]
    fn wipe_ghost_runtime_buffers_clears_sensitive_ephemeral_state() {
        let mut runtime = ghost_runtime();
        runtime.latest_invite_code = Some("invite".to_string());
        runtime.latest_group_invite_code = Some("group".to_string());
        runtime.receive_dir = Some("/tmp/recv".to_string());
        runtime.pending_invite_kind = Some(PendingInviteKind::Direct);
        runtime.ghost_handoffs.insert(
            "handoff-1".to_string(),
            GhostHandoff {
                handoff_id: "handoff-1".to_string(),
                peer_did: "did:nxf:peer".to_string(),
                peer_name: "Peer".to_string(),
                filename: "secret.txt".to_string(),
                staged_path: PathBuf::from("/tmp/handoff-1"),
                created_at_ms: 1,
            },
        );

        wipe_ghost_runtime_buffers(&mut runtime);

        assert!(runtime.logs.is_empty());
        assert!(runtime.latest_invite_code.is_none());
        assert!(runtime.latest_group_invite_code.is_none());
        assert!(runtime.receive_dir.is_none());
        assert!(runtime.ghost_handoffs.is_empty());
        assert!(runtime.pending_invite_kind.is_none());
    }

    #[test]
    fn ghost_runtime_tracks_staged_handoffs_from_transfer_events() {
        let mut runtime = ghost_runtime();
        apply_transfer_event_to_runtime(
            &mut runtime,
            &TransferEventPayload {
                event: "incoming_staged".to_string(),
                direction: "in".to_string(),
                peer_did: Some("did:nxf:peer".to_string()),
                peer_name: Some("Peer".to_string()),
                session_id: None,
                filename: Some("vault.zip".to_string()),
                reason: Some("ghost_secure_handoff_ready".to_string()),
                handoff_id: Some("handoff-123".to_string()),
                handoff_path: Some("/tmp/qypha-ghost-handoff/handoff-123".to_string()),
                transferred_chunks: None,
                total_chunks: None,
                transferred_bytes: None,
                total_bytes: None,
                percent: None,
                group_id: None,
                group_name: None,
                ts_ms: Some(42),
            },
            Some(TransferRuntimeEvent {
                agent: "ghost".to_string(),
                event: "incoming_staged".to_string(),
                direction: "in".to_string(),
                peer_did: contact_did_from_canonical_did("did:nxf:peer"),
                peer_contact_did: contact_did_from_canonical_did("did:nxf:peer"),
                peer_canonical_did: Some("did:nxf:peer".to_string()),
                peer_name: Some("Peer".to_string()),
                session_id: None,
                filename: Some("vault.zip".to_string()),
                reason: Some("ghost_secure_handoff_ready".to_string()),
                handoff_id: Some("handoff-123".to_string()),
                group_id: None,
                group_name: None,
                transferred_chunks: None,
                total_chunks: None,
                transferred_bytes: None,
                total_bytes: None,
                percent: None,
                ts_ms: 42,
            }),
        );

        let snapshot = snapshot_from_runtime(&runtime, 20);
        assert_eq!(snapshot.ghost_handoffs.len(), 1);
        assert_eq!(snapshot.ghost_handoffs[0].handoff_id, "handoff-123");
        assert_eq!(snapshot.ghost_handoffs[0].filename, "vault.zip");
        assert_eq!(snapshot.transfer_events.len(), 1);
        assert_eq!(snapshot.transfer_events[0].event, "incoming_staged");
    }

    #[test]
    fn export_handoff_moves_staged_file_into_receive_dir() {
        let staging_root = tempfile::tempdir().unwrap();
        let receive_root = tempfile::tempdir().unwrap();
        let staged_dir = staging_root.path().join("handoff-123");
        std::fs::create_dir_all(&staged_dir).unwrap();
        std::fs::write(staged_dir.join("ghost.txt"), b"ghost payload").unwrap();

        let handoff = GhostHandoff {
            handoff_id: "handoff-123".to_string(),
            peer_did: "did:nxf:peer".to_string(),
            peer_name: "Peer".to_string(),
            filename: "ghost.txt".to_string(),
            staged_path: staged_dir.clone(),
            created_at_ms: 7,
        };

        let exported = export_handoff_to_receive_dir(&handoff, receive_root.path()).unwrap();
        assert_eq!(exported, receive_root.path().join("ghost.txt"));
        assert_eq!(std::fs::read(&exported).unwrap(), b"ghost payload");
        assert!(!staged_dir.exists());
    }

    #[test]
    fn discover_agent_profiles_ignores_encrypted_sensitive_fields() {
        let root = tempfile::tempdir().unwrap();
        let config_root = root.path().join("agent-configs");
        std::fs::create_dir_all(&config_root).unwrap();
        let config_path = config_root.join("qypha_alice.toml");
        std::fs::write(
            &config_path,
            r#"[agent]
name = "alice"
did = "did:nxf:alice"

[network]
listen_port = 9444
transport_mode = "internet"
public_address = "ENC:ZmFrZQ=="

[network.mailbox]
endpoint = "ENC:ZmFrZQ=="
pool_endpoints = ["ENC:ZmFrZTE=", "ENC:ZmFrZTI="]

[logging]
mode = "safe"
"#,
        )
        .unwrap();

        let profiles = discover_agent_profiles(root.path());
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "alice");
        assert_eq!(profiles[0].mode, "safe");
        assert_eq!(profiles[0].transport, "internet");
        assert_eq!(profiles[0].listen_port, 9444);
        assert_eq!(
            profiles[0].config_path.as_deref(),
            Some(config_path.display().to_string().as_str())
        );
    }

    #[test]
    fn discover_agent_profiles_uses_root_scoped_initialized_agents_outside_workspace() {
        let root = tempfile::tempdir().unwrap();
        let agent_identity = root
            .path()
            .join(".qypha")
            .join("agents")
            .join("bob")
            .join("keys")
            .join("agent_identity.json");
        std::fs::create_dir_all(agent_identity.parent().unwrap()).unwrap();
        std::fs::write(&agent_identity, b"{}").unwrap();

        let profiles = discover_agent_profiles(root.path());
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "bob");
        assert_eq!(profiles[0].mode, "unknown");
        assert_eq!(profiles[0].transport, "unknown");
        assert_eq!(profiles[0].listen_port, 0);
        assert_eq!(
            profiles[0].config_path.as_deref(),
            Some(
                root.path()
                    .join("agent-configs")
                    .join("qypha_bob.toml")
                    .display()
                    .to_string()
                    .as_str()
            )
        );
    }

    #[test]
    fn runtime_tracks_pending_contact_requests_from_contact_did_lines() {
        let mut runtime = AgentRuntime::default();
        let canonical = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        let contact = contact_did_from_canonical_did(canonical).expect("contact did");

        let events = ingest_runtime_line(
            &mut runtime,
            format!("Contact request: alice ({})", contact),
        );

        assert!(events.is_empty());
        assert_eq!(runtime.pending_contact_requests.len(), 1);
        let request = runtime
            .pending_contact_requests
            .get(canonical)
            .expect("pending request");
        assert_eq!(request.name, "alice");
        assert_eq!(request.contact_did.as_deref(), Some(contact.as_str()));

        let snapshot = snapshot_from_runtime(&runtime, 32);
        assert_eq!(snapshot.pending_contact_requests.len(), 1);
        assert_eq!(snapshot.pending_contact_requests[0].did, contact);
    }

    #[test]
    fn runtime_promotes_pending_contact_request_to_known_peer_when_accepted() {
        let mut runtime = AgentRuntime::default();
        let canonical = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        let contact = contact_did_from_canonical_did(canonical).expect("contact did");

        ingest_runtime_line(
            &mut runtime,
            format!("Contact request: alice ({})", contact),
        );
        assert_eq!(runtime.pending_contact_requests.len(), 1);

        let events = ingest_runtime_line(
            &mut runtime,
            format!("Contact accepted: alice ({})", contact),
        );

        assert!(events.is_empty());
        assert!(runtime.pending_contact_requests.is_empty());
        let peer = runtime
            .peers
            .get(canonical)
            .expect("accepted request should become known peer");
        assert_eq!(peer.name, "alice");
        assert_eq!(peer.status, "connecting");
        assert_eq!(peer.contact_did.as_deref(), Some(contact.as_str()));
        assert!(peer.auto_reconnect);
    }

    #[test]
    fn runtime_drops_pending_contact_request_without_peer_when_rejected() {
        let mut runtime = AgentRuntime::default();
        let canonical = "did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b";
        let contact = contact_did_from_canonical_did(canonical).expect("contact did");

        ingest_runtime_line(
            &mut runtime,
            format!("Contact request: alice ({})", contact),
        );
        assert_eq!(runtime.pending_contact_requests.len(), 1);

        let events = ingest_runtime_line(
            &mut runtime,
            format!("Contact rejected: alice ({})", contact),
        );

        assert!(events.is_empty());
        assert!(runtime.pending_contact_requests.is_empty());
        assert!(!runtime.peers.contains_key(canonical));
    }
}

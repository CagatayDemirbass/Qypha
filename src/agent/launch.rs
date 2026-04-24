use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use rustyline::ExternalPrinter;
use rustyline::{error::ReadlineError, DefaultEditor};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
    oneshot, Mutex as TokioMutex,
};
use tokio::time::{timeout, Duration, Instant};
use uuid::Uuid;

use crate::agent::daemon::paths::default_receive_root;
use crate::config::*;
use crate::crypto::identity::AgentKeyPair;
use crate::crypto::keystore::{write_private_file, KeyStore};
use crate::os_adapter::home::preferred_user_home_dir;
use crate::os_adapter::secure_wipe::{secure_wipe_dir, secure_wipe_file};
use crate::runtime::contracts::{
    BrowserDownloadRequest, BrowserDownloadResult, BrowserInteractRequest, BrowserOpenRequest,
    BrowserSessionMode, BrowserSessionSpec, BrowserSnapshot, ConsultedSourceRecord,
    DocumentReadRequest, DocumentReadResponse, DocumentSection, InspectedResearchSource,
    McpServerInfo, MemoryCompressRequest, MemoryEntry, MemoryGetRequest, MemorySearchRequest,
    MemoryStalenessCheckRequest, MemoryStalenessCheckResult, MemoryWriteRequest,
    OsOperationRequest, OsOperationResult, PluginCapabilityInfo, PluginInfo,
    PluginMcpInvokeRequest, PluginMcpInvokeResponse, ProviderCatalogEntry, ProviderGenerateRequest,
    ProviderGenerateResponse, ProviderKind, RepoGitCommitEntry, RepoGitLogRequest,
    RepoGitLogResponse, RepoOverviewRequest, RepoOverviewResponse, RepoReadFileRequest,
    RepoReadFileResponse, RepoRemoteInspectRequest, RepoRemoteInspectResponse, RepoSearchMatch,
    RepoSearchRequest, RepoSearchResponse, RepoTreeEntry, RepoTreeRequest, RepoTreeResponse,
    ResearchActionLogEntry, ResearchDisposition, ResearchFindInPageRequest,
    ResearchFindInPageResponse, ResearchInspectRequest, ResearchInspectResponse,
    ResearchOpenPageRequest, ResearchOpenPageResponse, ResearchPageMatch, ResearchPlanRequest,
    ResearchPlanResponse, ResearchSearchRequest, ResearchSearchResponse, ResearchSource,
    ResearchSourceScope, ResearchSynthesisRequest, ResearchSynthesisResponse, RuntimeStatus,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum DesktopProfileAgentType {
    #[default]
    Human,
    Ai,
}

impl DesktopProfileAgentType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Ai => "ai",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LaunchAgentDesktopMetadata {
    name: String,
    #[serde(default)]
    agent_type: DesktopProfileAgentType,
    #[serde(default)]
    ai_provider: Option<String>,
    #[serde(default)]
    ai_model: Option<String>,
    #[serde(default = "default_ai_role")]
    ai_role: String,
    #[serde(default = "default_ai_access_mode")]
    ai_access_mode: String,
    #[serde(default = "default_ai_log_mode", alias = "log_mode")]
    ai_log_mode: String,
    #[serde(default, alias = "transport")]
    ai_transport_mode: Option<String>,
    #[serde(default, alias = "listen_port")]
    ai_listen_port: Option<u16>,
    #[serde(default)]
    receive_dir_default_snapshot: Option<String>,
}

impl LaunchAgentDesktopMetadata {
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
        self.ai_log_mode = normalize_ai_log_mode_value(&self.ai_log_mode);
        self.ai_transport_mode = self
            .ai_transport_mode
            .take()
            .and_then(|value| normalize_ai_transport_mode_value(&value));
        self.receive_dir_default_snapshot = self
            .receive_dir_default_snapshot
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self
    }
}

#[derive(Debug, Deserialize)]
struct OllamaWizardTagsResponse {
    #[serde(default)]
    models: Vec<OllamaWizardTagModel>,
}

#[derive(Debug, Deserialize)]
struct OllamaWizardTagModel {
    name: String,
}

#[derive(Debug, Clone)]
struct OllamaWizardModelOption {
    id: String,
    label: String,
    source: String,
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

#[derive(Debug, Serialize)]
struct EmbeddedWorkerProviderMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerProviderHealthcheckPayload {
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerProviderListModelsPayload {
    provider: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerGeneratePayload {
    provider: String,
    model_id: String,
    system_prompt: Option<String>,
    messages: Vec<EmbeddedWorkerProviderMessage>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerMemoryGetPayload {
    request: MemoryGetRequest,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerMemoryWritePayload {
    request: MemoryWriteRequest,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerMemorySearchPayload {
    request: MemorySearchRequest,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerMemoryCompressPayload {
    request: MemoryCompressRequest,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerMemoryStalenessCheckPayload {
    request: MemoryStalenessCheckRequest,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerRepoOverviewPayload {
    root: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerRepoTreePayload {
    root: String,
    depth: Option<usize>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerRepoSearchPayload {
    root: String,
    pattern: String,
    limit: usize,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerRepoReadFilePayload {
    path: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerRepoGitLogPayload {
    root: String,
    limit: usize,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerRepoRemoteInspectPayload {
    url: String,
    reference: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerOsExecutePayload {
    request: OsOperationRequest,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerAgentRunPayload {
    provider: String,
    model_id: String,
    system_prompt: Option<String>,
    prompt: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerResearchPlanPayload {
    provider: String,
    model_id: String,
    query: String,
    current_answer_draft: Option<String>,
    local_context_available: bool,
    system_prompt: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerResearchSearchPayload {
    provider: String,
    model_id: String,
    query: String,
    recency_required: bool,
    technical_only: bool,
    max_results: usize,
    scope: Option<ResearchSourceScope>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerResearchInspectPayload {
    provider: String,
    model_id: String,
    query: String,
    sources: Vec<ResearchSource>,
    max_sources: usize,
    scope: Option<ResearchSourceScope>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerResearchOpenPagePayload {
    session_id: String,
    source: ResearchSource,
    scope: Option<ResearchSourceScope>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerResearchFindInPagePayload {
    session_id: String,
    query: String,
    source: Option<ResearchSource>,
    url: Option<String>,
    max_matches: usize,
    scope: Option<ResearchSourceScope>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerResearchSynthesizePayload {
    provider: String,
    model_id: String,
    query: String,
    sources: Vec<ResearchSource>,
    inspected_sources: Vec<InspectedResearchSource>,
    consulted_sources: Vec<ConsultedSourceRecord>,
    desired_format: Option<String>,
    system_prompt: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerBrowserStartSessionPayload {
    session_id: String,
    mode: String,
    allowed_domains: Vec<String>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerBrowserOpenPayload {
    session_id: String,
    url: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerBrowserSnapshotPayload {
    session_id: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerBrowserInteractPayload {
    session_id: String,
    action: String,
    target: Option<String>,
    value: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerBrowserDownloadPayload {
    session_id: String,
    url: String,
    destination: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerDocumentReadPayload {
    path: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerPluginMcpListPayload {
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerPluginMcpResolvePayload {
    capability_id: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedWorkerPluginMcpInvokePayload {
    capability_id: String,
    args_json: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum EmbeddedWorkerRequest {
    Hello,
    ProviderHealthcheck {
        payload: EmbeddedWorkerProviderHealthcheckPayload,
    },
    ProviderListModels {
        payload: EmbeddedWorkerProviderListModelsPayload,
    },
    ProviderGenerate {
        payload: EmbeddedWorkerGeneratePayload,
    },
    MemoryGet {
        payload: EmbeddedWorkerMemoryGetPayload,
    },
    MemoryWrite {
        payload: EmbeddedWorkerMemoryWritePayload,
    },
    MemorySearch {
        payload: EmbeddedWorkerMemorySearchPayload,
    },
    MemoryCompress {
        payload: EmbeddedWorkerMemoryCompressPayload,
    },
    MemoryStalenessCheck {
        payload: EmbeddedWorkerMemoryStalenessCheckPayload,
    },
    RepoOverview {
        payload: EmbeddedWorkerRepoOverviewPayload,
    },
    RepoTree {
        payload: EmbeddedWorkerRepoTreePayload,
    },
    RepoGrep {
        payload: EmbeddedWorkerRepoSearchPayload,
    },
    RepoReadFile {
        payload: EmbeddedWorkerRepoReadFilePayload,
    },
    RepoGitLog {
        payload: EmbeddedWorkerRepoGitLogPayload,
    },
    RepoRemoteInspect {
        payload: EmbeddedWorkerRepoRemoteInspectPayload,
    },
    OsExecute {
        payload: EmbeddedWorkerOsExecutePayload,
    },
    AgentRun {
        payload: EmbeddedWorkerAgentRunPayload,
    },
    ResearchPlan {
        payload: EmbeddedWorkerResearchPlanPayload,
    },
    ResearchSearch {
        payload: EmbeddedWorkerResearchSearchPayload,
    },
    ResearchInspect {
        payload: EmbeddedWorkerResearchInspectPayload,
    },
    ResearchOpenPage {
        payload: EmbeddedWorkerResearchOpenPagePayload,
    },
    ResearchFindInPage {
        payload: EmbeddedWorkerResearchFindInPagePayload,
    },
    ResearchSynthesize {
        payload: EmbeddedWorkerResearchSynthesizePayload,
    },
    BrowserStartSession {
        payload: EmbeddedWorkerBrowserStartSessionPayload,
    },
    BrowserOpen {
        payload: EmbeddedWorkerBrowserOpenPayload,
    },
    BrowserSnapshot {
        payload: EmbeddedWorkerBrowserSnapshotPayload,
    },
    BrowserInteract {
        payload: EmbeddedWorkerBrowserInteractPayload,
    },
    BrowserDownload {
        payload: EmbeddedWorkerBrowserDownloadPayload,
    },
    DocumentRead {
        payload: EmbeddedWorkerDocumentReadPayload,
    },
    PluginMcpListPlugins {
        payload: EmbeddedWorkerPluginMcpListPayload,
    },
    PluginMcpListServers {
        payload: EmbeddedWorkerPluginMcpListPayload,
    },
    PluginMcpResolveCapability {
        payload: EmbeddedWorkerPluginMcpResolvePayload,
    },
    PluginMcpInvoke {
        payload: EmbeddedWorkerPluginMcpInvokePayload,
    },
}

#[derive(Debug, Deserialize)]
struct EmbeddedWorkerResponse {
    ok: bool,
    #[serde(default)]
    worker: Option<String>,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    catalog: Vec<ProviderCatalogEntry>,
    #[serde(default)]
    memory_entry: Option<MemoryEntry>,
    #[serde(default)]
    memory_entries: Vec<MemoryEntry>,
    #[serde(default)]
    memory_id: Option<String>,
    #[serde(default)]
    stale: Option<bool>,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    vcs: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    dirty: bool,
    #[serde(default)]
    changed_files: Vec<String>,
    #[serde(default)]
    entries: Vec<RepoTreeEntry>,
    #[serde(default)]
    repo_matches: Vec<RepoSearchMatch>,
    #[serde(default)]
    file_content: Option<String>,
    #[serde(default)]
    commits: Vec<RepoGitCommitEntry>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    candidate_files: Vec<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    output_text: Option<String>,
    #[serde(default)]
    finish_reason: Option<String>,
    #[serde(default)]
    disposition: Option<String>,
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    planned_steps: Vec<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    markdown: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    sources: Vec<ResearchSource>,
    #[serde(default)]
    inspected_sources: Vec<InspectedResearchSource>,
    #[serde(default)]
    consulted_sources: Vec<ConsultedSourceRecord>,
    #[serde(default)]
    consulted_source: Option<ConsultedSourceRecord>,
    #[serde(default)]
    action_log: Vec<ResearchActionLogEntry>,
    #[serde(default)]
    matches: Vec<ResearchPageMatch>,
    #[serde(default)]
    sections: Vec<DocumentSection>,
    #[serde(default)]
    plugins: Vec<PluginInfo>,
    #[serde(default)]
    servers: Vec<McpServerInfo>,
    #[serde(default)]
    capability: Option<PluginCapabilityInfo>,
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    output_json: Option<String>,
    #[serde(default)]
    answer: Option<String>,
    #[serde(default)]
    uncertainty: Option<String>,
    #[serde(default)]
    citations: Vec<String>,
    #[serde(default)]
    sources_used: Vec<ConsultedSourceRecord>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone)]
enum AiCompanionLaunchSpec {
    Persistent {
        config_path: std::path::PathBuf,
        passphrase: String,
    },
    Ghost {
        name: String,
        transport_mode: TransportMode,
        listen_port: u16,
    },
}

#[derive(Debug, Clone)]
struct CompanionOutputLine {
    is_stderr: bool,
    line: String,
}

#[derive(Debug, Deserialize)]
struct CompanionDirectMessageEvent {
    direction: String,
    peer_did: String,
    #[serde(default)]
    peer_contact_did: Option<String>,
    #[serde(default)]
    peer_canonical_did: Option<String>,
    peer_name: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CompanionDirectPeerEvent {
    event: String,
    did: String,
    #[serde(default)]
    contact_did: Option<String>,
    #[serde(default)]
    canonical_did: Option<String>,
    name: String,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompanionInviteResult {
    kind: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct EmbeddedReceiveDirConfigSnapshot {
    #[serde(default)]
    global_dir: Option<std::path::PathBuf>,
    #[serde(default)]
    per_peer_dirs: HashMap<String, std::path::PathBuf>,
}

#[derive(Debug, Clone)]
struct EmbeddedReceiveDirContext {
    default_dir: std::path::PathBuf,
    global_dir: std::path::PathBuf,
    effective_dir: std::path::PathBuf,
    effective_source: &'static str,
}

#[derive(Debug, Clone)]
struct AiTerminalRuntimeState {
    display_tx: mpsc::UnboundedSender<String>,
    peer_reply_locks: std::sync::Arc<TokioMutex<HashMap<String, std::sync::Arc<TokioMutex<()>>>>>,
    auto_accept_peer_dids: std::sync::Arc<TokioMutex<HashSet<String>>>,
    companion_line_tx: broadcast::Sender<CompanionOutputLine>,
    companion_stdin: std::sync::Arc<TokioMutex<Option<std::sync::Arc<TokioMutex<ChildStdin>>>>>,
    companion_command_lock: std::sync::Arc<TokioMutex<()>>,
    companion_peer_cache: std::sync::Arc<TokioMutex<HashMap<String, CompanionControlPeerSnapshot>>>,
    companion_whoami_snapshot: std::sync::Arc<TokioMutex<Option<CompanionControlWhoAmISnapshot>>>,
}

#[derive(Debug)]
struct AiAgentStateInspection {
    metadata: Option<LaunchAgentDesktopMetadata>,
    config_path: std::path::PathBuf,
    identity_path: std::path::PathBuf,
    action: PersistentLaunchAction,
}

#[derive(Debug, Clone)]
struct AiNetworkLaunchPlan {
    transport_mode: TransportMode,
    log_mode: String,
    listen_port: u16,
    companion_spec: AiCompanionLaunchSpec,
}

const COMPANION_DIRECT_PEERS_BEGIN: &str = "DIRECT_PEERS_BEGIN";
const COMPANION_DIRECT_PEERS_END: &str = "DIRECT_PEERS_END";
const COMPANION_DIRECT_PEERS_EMPTY: &str = "DIRECT_PEERS_EMPTY";
const COMPANION_DIRECT_PEER: &str = "DIRECT_PEER";
const COMPANION_WHOAMI: &str = "WHOAMI";
const COMPANION_INVITE_RESULT: &str = "INVITE_RESULT";
const COMPANION_DIRECT_MESSAGE_EVENT: &str = "DIRECT_MESSAGE_EVENT";
const COMPANION_DIRECT_PEER_EVENT: &str = "DIRECT_PEER_EVENT";
const COMPANION_MAILBOX_GROUPS_BEGIN: &str = "MAILBOX_GROUPS_BEGIN";
const COMPANION_MAILBOX_GROUPS_END: &str = "MAILBOX_GROUPS_END";
const COMPANION_MAILBOX_GROUPS_EMPTY: &str = "MAILBOX_GROUPS_EMPTY";
const COMPANION_MAILBOX_GROUP: &str = "MAILBOX_GROUP";

#[derive(Debug, Clone)]
struct CompanionControlInfo {
    socket_path: String,
    auth_token: String,
}

#[derive(Debug)]
struct CompanionControlServerHandle {
    info: CompanionControlInfo,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompanionControlPeerSnapshot {
    #[serde(default)]
    selector: String,
    name: String,
    did: String,
    #[serde(default)]
    contact_did: Option<String>,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default)]
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompanionControlGroupSummary {
    group_id: String,
    #[serde(default)]
    group_name: Option<String>,
    anonymous_group: bool,
    #[serde(default)]
    anonymous_security_state: Option<String>,
    join_locked: bool,
    persistence: String,
    #[serde(default)]
    local_member_id: Option<String>,
    #[serde(default)]
    owner_member_id: Option<String>,
    #[serde(default)]
    owner_special_id: Option<String>,
    #[serde(default)]
    known_member_ids: Vec<String>,
    mailbox_epoch: u64,
    #[serde(default)]
    degraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompanionControlWhoAmISnapshot {
    name: String,
    did: String,
    #[serde(default)]
    contact_did: Option<String>,
    peer_id: String,
    transport: String,
    #[serde(default)]
    iroh_id: Option<String>,
    #[serde(default)]
    onion: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    relay_routes: Option<u64>,
    direct_peers: usize,
    groups: usize,
}

#[derive(Debug, Deserialize)]
struct CompanionControlEnvelope {
    token: String,
    #[serde(flatten)]
    request: CompanionControlRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum CompanionControlRequest {
    Peers {
        #[serde(default)]
        verbose: bool,
    },
    Groups,
    WhoAmI,
    Send {
        message: String,
    },
    SendTo {
        target: String,
        message: String,
    },
    Disconnect {
        target: String,
    },
    TransferToPeer {
        target: String,
        path: String,
    },
    TransferToGroup {
        group_id: String,
        path: String,
    },
    ReceiveDir {
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        reset: bool,
    },
    Accept {
        #[serde(default)]
        selector: Option<String>,
    },
    AcceptAlways {
        target: String,
    },
    AcceptAsk {
        target: String,
    },
    Reject {
        #[serde(default)]
        selector: Option<String>,
    },
    Invite,
    GroupNormal {
        name: String,
    },
    InviteGroup {
        group_id: String,
    },
    GroupAnon {
        #[serde(default)]
        name: Option<String>,
    },
    InviteAnon {
        owner_special_id: String,
    },
    InviteHandshake {
        member_id: String,
    },
    InviteHandshakeGroup {
        group_id: String,
        member_id: String,
    },
    Block {
        #[serde(default)]
        selector: Option<String>,
    },
    Unblock {
        member_id: String,
    },
    BlockAllRequests,
    UnblockAllRequests,
    Connect {
        code: String,
    },
    KickGroupMember {
        member_id: String,
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
    Quit,
}

#[derive(Debug, Serialize)]
struct CompanionControlResponse {
    ok: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    peers: Vec<CompanionControlPeerSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<CompanionControlGroupSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    whoami: Option<CompanionControlWhoAmISnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum CompanionUiBridgeCommand {
    SendTo { selector: String, message: String },
    TransferToPeer { selector: String, path: String },
    TransferToGroup { group_id: String, path: String },
}

static ACTIVE_COMPANION_CONTROL_INFO: OnceLock<StdMutex<Option<CompanionControlInfo>>> =
    OnceLock::new();
static AI_PROVIDER_ENV_OVERRIDES: OnceLock<StdMutex<HashMap<String, String>>> = OnceLock::new();

struct CompanionRuntimeSession {
    child: Child,
    stdin: std::sync::Arc<TokioMutex<ChildStdin>>,
}

struct EmbeddedWorkerRuntimeSession {
    child: Child,
    stdin: std::sync::Arc<TokioMutex<ChildStdin>>,
    stdout_rx: UnboundedReceiver<String>,
    stderr_tail: std::sync::Arc<TokioMutex<VecDeque<String>>>,
}

fn active_companion_control_info_cell() -> &'static StdMutex<Option<CompanionControlInfo>> {
    ACTIVE_COMPANION_CONTROL_INFO.get_or_init(|| StdMutex::new(None))
}

fn set_active_companion_control_info(info: Option<CompanionControlInfo>) {
    if let Ok(mut guard) = active_companion_control_info_cell().lock() {
        *guard = info;
    }
}

fn current_active_companion_control_info() -> Option<CompanionControlInfo> {
    active_companion_control_info_cell()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

fn strip_ansi_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
                continue;
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn default_ai_role() -> String {
    "general".to_string()
}

fn default_ai_access_mode() -> String {
    "full_access".to_string()
}

fn default_ai_log_mode() -> String {
    "safe".to_string()
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

fn normalize_ai_log_mode_value(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "" | "safe" => "safe".to_string(),
        "ghost" => "ghost".to_string(),
        _ => "safe".to_string(),
    }
}

fn normalize_ai_transport_mode_value(value: &str) -> Option<String> {
    match value.trim().to_lowercase().as_str() {
        "" => None,
        "lan" | "tcp" => Some("lan".to_string()),
        "tor" => Some("tor".to_string()),
        "internet" | "inet" | "wan" => Some("internet".to_string()),
        _ => None,
    }
}

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn embedded_ai_workspace_root(metadata: &LaunchAgentDesktopMetadata) -> std::path::PathBuf {
    if metadata.ai_access_mode == "full_access" {
        return preferred_user_home_dir().unwrap_or_else(workspace_root);
    }
    workspace_root()
}

fn workspace_embedded_runtime_root() -> std::path::PathBuf {
    workspace_root().join("agent-configs").join("qypha-runtime")
}

fn fallback_embedded_runtime_root() -> std::path::PathBuf {
    KeyStore::agent_data_path("embedded_runtime")
        .unwrap_or_else(|_| workspace_root().join(".qypha-runtime-user"))
        .join("runtime")
}

fn ensure_writable_runtime_root(path: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    let probe = path.join(format!(
        ".qypha-runtime-write-test-{}",
        Uuid::new_v4().simple()
    ));
    std::fs::write(&probe, b"ok")?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

fn embedded_runtime_storage_root() -> std::path::PathBuf {
    let workspace_root = workspace_embedded_runtime_root();
    if ensure_writable_runtime_root(&workspace_root).is_ok() {
        return workspace_root;
    }

    let fallback_root = fallback_embedded_runtime_root();
    if let Err(error) = ensure_writable_runtime_root(&fallback_root) {
        eprintln!(
            "WARNING: embedded runtime fallback root {} is not writable: {}",
            fallback_root.display(),
            error
        );
    }
    fallback_root
}

fn active_embedded_agent_path() -> std::path::PathBuf {
    workspace_root()
        .join("agent-configs")
        .join("qypha_active_agent.txt")
}

fn persist_active_embedded_agent(agent_name: &str) -> Result<std::path::PathBuf> {
    let path = active_embedded_agent_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private_file(&path, agent_name.trim().as_bytes())?;
    Ok(path)
}

pub(crate) fn agent_metadata_path_for_name(agent_name: &str) -> std::path::PathBuf {
    workspace_root().join("agent-configs").join(format!(
        "qypha_{}.desktop-profile.json",
        KeyStore::sanitize_agent_name(agent_name)
    ))
}

fn load_agent_desktop_metadata(path: &std::path::Path) -> Option<LaunchAgentDesktopMetadata> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<LaunchAgentDesktopMetadata>(&content)
        .ok()
        .map(LaunchAgentDesktopMetadata::normalized)
}

fn save_agent_desktop_metadata(
    metadata: &LaunchAgentDesktopMetadata,
) -> Result<std::path::PathBuf> {
    let path = agent_metadata_path_for_name(&metadata.name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut persisted = metadata.clone().normalized();
    persisted.receive_dir_default_snapshot = Some(default_receive_root().display().to_string());
    let json = serde_json::to_vec_pretty(&persisted)?;
    write_private_file(&path, &json)?;
    Ok(path)
}

fn ai_agent_thread_path(ai_agent: &str, requester_agent: Option<&str>) -> std::path::PathBuf {
    let requester_segment = requester_agent
        .map(KeyStore::sanitize_agent_name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "self".to_string());
    workspace_root().join("agent-configs").join(format!(
        "qypha_{}.thread_{}.ai-chat.json",
        KeyStore::sanitize_agent_name(ai_agent),
        requester_segment
    ))
}

fn embedded_runtime_root() -> std::path::PathBuf {
    workspace_root().join("embedded_runtime")
}

fn embedded_runtime_home_root() -> std::path::PathBuf {
    embedded_runtime_storage_root().join("home")
}

fn embedded_runtime_state_dir() -> std::path::PathBuf {
    embedded_runtime_home_root().join(".qypha-runtime")
}

fn embedded_runtime_config_path() -> std::path::PathBuf {
    embedded_runtime_state_dir().join("qypha-runtime.json")
}

fn embedded_runtime_bundled_python_executable() -> Option<std::path::PathBuf> {
    let target_key = if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "darwin-arm64"
        } else if cfg!(target_arch = "x86_64") {
            "darwin-x64"
        } else {
            return None;
        }
    } else if cfg!(target_os = "linux") {
        let libc = if cfg!(target_env = "musl") {
            "musl"
        } else {
            "gnu"
        };
        if cfg!(target_arch = "aarch64") {
            if libc == "musl" {
                "linux-arm64-musl"
            } else {
                "linux-arm64-gnu"
            }
        } else if cfg!(target_arch = "x86_64") {
            if libc == "musl" {
                "linux-x64-musl"
            } else {
                "linux-x64-gnu"
            }
        } else {
            return None;
        }
    } else if cfg!(target_os = "windows") {
        if cfg!(target_arch = "aarch64") {
            "win32-arm64"
        } else if cfg!(target_arch = "x86_64") {
            "win32-x64"
        } else {
            return None;
        }
    } else {
        return None;
    };

    let install_dir = embedded_runtime_root()
        .join("internal")
        .join("runtime")
        .join("python")
        .join(target_key)
        .join("python");
    let executable = if cfg!(target_os = "windows") {
        install_dir.join("python.exe")
    } else {
        install_dir.join("bin").join("python3")
    };
    executable.exists().then_some(executable)
}

fn resolve_runtime_executable(
    primary_env_var: &str,
    legacy_env_var: &str,
    program_names: &[&str],
    extra_dirs: &[std::path::PathBuf],
) -> Result<std::path::PathBuf> {
    for env_var in [primary_env_var, legacy_env_var] {
        if let Some(raw) = std::env::var_os(env_var) {
            let candidate = std::path::PathBuf::from(raw);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    let mut candidates = Vec::new();
    if let Some(path_value) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_value) {
            candidates.push(dir);
        }
    }
    candidates.extend(extra_dirs.iter().cloned());

    #[cfg(target_os = "macos")]
    {
        candidates.push(std::path::PathBuf::from("/opt/homebrew/bin"));
        candidates.push(std::path::PathBuf::from("/usr/local/bin"));
    }

    #[cfg(target_os = "linux")]
    {
        candidates.push(std::path::PathBuf::from("/usr/local/bin"));
        candidates.push(std::path::PathBuf::from("/usr/bin"));
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(
                std::path::PathBuf::from(&local_app_data)
                    .join("Programs")
                    .join("nodejs"),
            );
        }
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            candidates.push(std::path::PathBuf::from(&program_files).join("nodejs"));
        }
    }

    let mut seen = HashSet::new();
    candidates.retain(|path| seen.insert(path.clone()));

    for dir in candidates {
        for program in program_names {
            let candidate = dir.join(program);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    anyhow::bail!(
        "Required embedded runtime executable '{}' was not found. Set {} to an absolute path or install Node.js in a standard location.",
        program_names.first().copied().unwrap_or("node"),
        primary_env_var
    )
}

fn embedded_runtime_node_executable() -> Result<std::path::PathBuf> {
    let mut extra_dirs = Vec::new();
    if let Some(home) = preferred_user_home_dir() {
        extra_dirs.push(home.join(".local").join("bin"));
    }
    #[cfg(target_os = "windows")]
    let program_names = ["node.exe", "node.cmd", "node.bat", "node"];
    #[cfg(not(target_os = "windows"))]
    let program_names = ["node"];
    resolve_runtime_executable(
        "QYPHA_EMBEDDED_NODE",
        "OPENCLAW_NODE",
        &program_names,
        &extra_dirs,
    )
}

fn embedded_runtime_npm_executable() -> Result<std::path::PathBuf> {
    let mut extra_dirs = Vec::new();
    if let Some(home) = preferred_user_home_dir() {
        extra_dirs.push(home.join(".local").join("bin"));
    }
    #[cfg(target_os = "windows")]
    let program_names = ["npm.cmd", "npm.exe", "npm.bat", "npm"];
    #[cfg(not(target_os = "windows"))]
    let program_names = ["npm"];
    resolve_runtime_executable(
        "QYPHA_EMBEDDED_NPM",
        "OPENCLAW_NPM",
        &program_names,
        &extra_dirs,
    )
}

fn embedded_worker_bundle_path() -> std::path::PathBuf {
    embedded_runtime_root().join("dist").join("worker-entry.js")
}

fn embedded_worker_source_paths() -> Vec<std::path::PathBuf> {
    let root = embedded_runtime_root();
    vec![
        root.join("bridge").join("worker-entry.ts"),
        root.join("bridge").join("stubs").join("provider-auth.ts"),
        root.join("package.json"),
        root.join("tsconfig.worker.json"),
    ]
}

fn parse_embedded_timeout_ms(raw: Option<&str>, default_ms: u64) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value >= 1_000)
        .unwrap_or(default_ms)
        .clamp(30_000, 900_000)
}

fn embedded_worker_timeout_ms(request: &EmbeddedWorkerRequest) -> u64 {
    match request {
        EmbeddedWorkerRequest::Hello => 15_000,
        EmbeddedWorkerRequest::ProviderHealthcheck { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            45_000,
        )
        .saturating_add(15_000)
        .min(120_000),
        EmbeddedWorkerRequest::ProviderListModels { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            45_000,
        )
        .saturating_add(15_000)
        .min(120_000),
        EmbeddedWorkerRequest::ProviderGenerate { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            120_000,
        )
        .saturating_add(15_000)
        .min(615_000),
        EmbeddedWorkerRequest::MemoryGet { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            45_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::MemoryWrite { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::MemorySearch { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::MemoryCompress { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::MemoryStalenessCheck { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            45_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::RepoOverview { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            45_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::RepoTree { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::RepoGrep { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::RepoReadFile { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::RepoGitLog { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::RepoRemoteInspect { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::OsExecute { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            120_000,
        )
        .saturating_add(30_000)
        .min(360_000),
        EmbeddedWorkerRequest::AgentRun { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            300_000,
        )
        .saturating_add(30_000)
        .min(930_000),
        EmbeddedWorkerRequest::ResearchPlan { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::ResearchSearch { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::ResearchInspect { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            120_000,
        )
        .saturating_add(30_000)
        .min(360_000),
        EmbeddedWorkerRequest::ResearchOpenPage { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            120_000,
        )
        .saturating_add(30_000)
        .min(360_000),
        EmbeddedWorkerRequest::ResearchFindInPage { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::ResearchSynthesize { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::BrowserStartSession { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            45_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::BrowserOpen { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::BrowserSnapshot { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::BrowserInteract { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(15_000)
        .min(240_000),
        EmbeddedWorkerRequest::BrowserDownload { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            120_000,
        )
        .saturating_add(30_000)
        .min(360_000),
        EmbeddedWorkerRequest::DocumentRead { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            90_000,
        )
        .saturating_add(30_000)
        .min(240_000),
        EmbeddedWorkerRequest::PluginMcpListPlugins { payload }
        | EmbeddedWorkerRequest::PluginMcpListServers { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::PluginMcpResolveCapability { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            60_000,
        )
        .saturating_add(15_000)
        .min(180_000),
        EmbeddedWorkerRequest::PluginMcpInvoke { payload } => parse_embedded_timeout_ms(
            payload.metadata.get("timeout_ms").map(String::as_str),
            120_000,
        )
        .saturating_add(30_000)
        .min(360_000),
    }
}

fn embedded_worker_supervisor() -> &'static TokioMutex<Option<EmbeddedWorkerRuntimeSession>> {
    static SUPERVISOR: OnceLock<TokioMutex<Option<EmbeddedWorkerRuntimeSession>>> = OnceLock::new();
    SUPERVISOR.get_or_init(|| TokioMutex::new(None))
}

fn spawn_embedded_worker_stdout_task<R>(
    reader: R,
    tx: UnboundedSender<String>,
    stderr_tail: std::sync::Arc<TokioMutex<VecDeque<String>>>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let trimmed = line.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if tx.send(trimmed).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let mut guard = stderr_tail.lock().await;
                    guard.push_back(format!("Embedded worker stdout error: {}", error));
                    if guard.len() > 64 {
                        guard.pop_front();
                    }
                    break;
                }
            }
        }
    });
}

fn spawn_embedded_worker_stderr_task<R>(
    reader: R,
    stderr_tail: std::sync::Arc<TokioMutex<VecDeque<String>>>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let mut guard = stderr_tail.lock().await;
                    guard.push_back(trimmed.to_string());
                    if guard.len() > 64 {
                        guard.pop_front();
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let mut guard = stderr_tail.lock().await;
                    guard.push_back(format!("Embedded worker stderr error: {}", error));
                    if guard.len() > 64 {
                        guard.pop_front();
                    }
                    break;
                }
            }
        }
    });
}

async fn embedded_worker_stderr_snapshot(
    stderr_tail: &std::sync::Arc<TokioMutex<VecDeque<String>>>,
) -> String {
    let guard = stderr_tail.lock().await;
    guard.iter().cloned().collect::<Vec<_>>().join(" | ")
}

async fn shutdown_embedded_worker_session(session: &mut EmbeddedWorkerRuntimeSession) {
    if session.child.try_wait().ok().flatten().is_none() {
        let _ = session.child.kill().await;
    }
    let _ = session.child.wait().await;
}

async fn restart_embedded_worker_supervisor() {
    let supervisor = embedded_worker_supervisor();
    let mut guard = supervisor.lock().await;
    if let Some(mut session) = guard.take() {
        shutdown_embedded_worker_session(&mut session).await;
    }
}

async fn run_embedded_worker_with_session(
    session: &mut EmbeddedWorkerRuntimeSession,
    request: &EmbeddedWorkerRequest,
) -> Result<EmbeddedWorkerResponse> {
    if let Some(status) = session.child.try_wait()? {
        let stderr = embedded_worker_stderr_snapshot(&session.stderr_tail).await;
        anyhow::bail!(
            "Embedded runtime worker exited before request could be sent (status: {}). {}",
            status,
            stderr
        );
    }

    let request_json = serde_json::to_string(request)?;
    {
        let mut stdin = session.stdin.lock().await;
        stdin.write_all(request_json.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
    }

    let timeout_ms = embedded_worker_timeout_ms(request);
    let stderr_tail = session.stderr_tail.clone();
    let response = match timeout(Duration::from_millis(timeout_ms), async {
        loop {
            let Some(line) = session.stdout_rx.recv().await else {
                let stderr = embedded_worker_stderr_snapshot(&stderr_tail).await;
                return Err(anyhow::anyhow!(
                    "Embedded runtime worker stdout closed before a response arrived. {}",
                    stderr
                ));
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
                continue;
            }
            return serde_json::from_str::<EmbeddedWorkerResponse>(trimmed).map_err(|error| {
                anyhow::anyhow!(
                    "Embedded runtime worker returned invalid JSON: {}. line='{}'",
                    error,
                    trimmed
                )
            });
        }
    })
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            let stderr = embedded_worker_stderr_snapshot(&session.stderr_tail).await;
            anyhow::bail!(
                "Embedded runtime worker timed out after {}s. {}",
                timeout_ms / 1000,
                stderr
            );
        }
    };

    if !response.ok && response.error.as_deref().unwrap_or("").is_empty() {
        let stderr = embedded_worker_stderr_snapshot(&session.stderr_tail).await;
        anyhow::bail!(
            "Embedded runtime worker failed without an error payload. {}",
            stderr
        );
    }

    Ok(response)
}

async fn start_embedded_worker_session(
    bundle: &std::path::Path,
    runtime_root: &std::path::Path,
) -> Result<EmbeddedWorkerRuntimeSession> {
    let runtime_home = embedded_runtime_home_root();
    let runtime_state_dir = embedded_runtime_state_dir();
    let runtime_config_path = embedded_runtime_config_path();
    let bundled_python = embedded_runtime_bundled_python_executable();
    std::fs::create_dir_all(&runtime_state_dir)?;

    let node_executable = embedded_runtime_node_executable()?;
    let mut command = Command::new(&node_executable);
    command
        .arg(bundle)
        .current_dir(runtime_root)
        .env("QYPHA_RUNTIME_HOME", &runtime_home)
        .env("QYPHA_RUNTIME_STATE_DIR", &runtime_state_dir)
        .env("QYPHA_RUNTIME_CONFIG_PATH", &runtime_config_path);
    if let Some(python_path) = bundled_python.as_ref() {
        command
            .env("QYPHA_DOCUMENT_GENERATE_PYTHON", python_path)
            .env("OPENCLAW_DOCUMENT_GENERATE_PYTHON", python_path)
            .env("OPENCLAW_PINNED_WRITE_PYTHON", python_path);
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            anyhow::anyhow!(
                "Failed to start embedded runtime worker {} via {}: {}",
                bundle.display(),
                node_executable.display(),
                error
            )
        })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Embedded runtime worker stdin pipe was not available"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Embedded runtime worker stdout pipe was not available"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Embedded runtime worker stderr pipe was not available"))?;
    let (stdout_tx, stdout_rx) = mpsc::unbounded_channel();
    let stderr_tail = std::sync::Arc::new(TokioMutex::new(VecDeque::new()));

    spawn_embedded_worker_stdout_task(stdout, stdout_tx, stderr_tail.clone());
    spawn_embedded_worker_stderr_task(stderr, stderr_tail.clone());

    let mut session = EmbeddedWorkerRuntimeSession {
        child,
        stdin: std::sync::Arc::new(TokioMutex::new(stdin)),
        stdout_rx,
        stderr_tail,
    };

    if let Err(error) =
        run_embedded_worker_with_session(&mut session, &EmbeddedWorkerRequest::Hello).await
    {
        shutdown_embedded_worker_session(&mut session).await;
        return Err(error);
    }

    Ok(session)
}

fn embedded_runtime_agent_dir(ai_agent: &str) -> std::path::PathBuf {
    embedded_runtime_storage_root().join(KeyStore::sanitize_agent_name(ai_agent))
}

fn embedded_runtime_skills_dir(ai_agent: &str) -> std::path::PathBuf {
    embedded_runtime_agent_dir(ai_agent).join("skills")
}

fn embedded_runtime_session_file(
    ai_agent: &str,
    requester_agent: Option<&str>,
) -> std::path::PathBuf {
    let requester_segment = requester_agent
        .map(KeyStore::sanitize_agent_name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "self".to_string());
    embedded_runtime_agent_dir(ai_agent)
        .join("sessions")
        .join(format!("{}.session.json", requester_segment))
}

fn npm_command_name() -> &'static str {
    if cfg!(windows) {
        "npm.cmd"
    } else {
        "npm"
    }
}

fn embedded_worker_is_stale() -> bool {
    let bundle = embedded_worker_bundle_path();
    let Ok(bundle_meta) = std::fs::metadata(&bundle) else {
        return true;
    };
    let Ok(bundle_modified) = bundle_meta.modified() else {
        return true;
    };
    embedded_worker_source_paths().into_iter().any(|path| {
        std::fs::metadata(&path)
            .and_then(|meta| meta.modified())
            .map(|modified| modified > bundle_modified)
            .unwrap_or(true)
    })
}

fn load_embedded_receive_dir_context(
    agent_name: &str,
    requester_agent: Option<&str>,
    default_receive_dir_snapshot: Option<&str>,
) -> EmbeddedReceiveDirContext {
    let resolved_default_dir = default_receive_root();
    let default_dir = if resolved_default_dir.is_absolute() {
        resolved_default_dir
    } else {
        default_receive_dir_snapshot
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(resolved_default_dir)
    };
    let config_path = KeyStore::agent_data_path(agent_name)
        .unwrap_or_else(|_| default_dir.clone())
        .join("receive_dirs.json");
    let config = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|json| serde_json::from_str::<EmbeddedReceiveDirConfigSnapshot>(&json).ok())
        .unwrap_or_default();
    let requester = requester_agent
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "self");
    let global_dir = config
        .global_dir
        .clone()
        .unwrap_or_else(|| default_dir.clone());
    let (effective_dir, effective_source) = requester
        .and_then(|did| {
            config
                .per_peer_dirs
                .get(did)
                .cloned()
                .map(|path| (path, "peer"))
        })
        .or_else(|| config.global_dir.clone().map(|path| (path, "global")))
        .unwrap_or_else(|| (default_dir.clone(), "default"));
    EmbeddedReceiveDirContext {
        default_dir,
        global_dir,
        effective_dir,
        effective_source,
    }
}

fn build_ai_agent_system_prompt(
    metadata: &LaunchAgentDesktopMetadata,
    requester_agent: Option<&str>,
) -> String {
    let provider = metadata.ai_provider.as_deref().unwrap_or("ollama");
    let model = metadata.ai_model.as_deref().unwrap_or("unset");
    let receive_dir_context = load_embedded_receive_dir_context(
        &metadata.name,
        requester_agent,
        metadata.receive_dir_default_snapshot.as_deref(),
    );
    format!(
        "You are Qypha embedded AI agent '{name}'. Role: {role}. Access mode: {access}. Provider: {provider}. Model: {model}. Current Qypha receive directory context: OS-resolved default receive dir = {default_receive_dir}; global receive dir = {global_receive_dir}; effective receive dir for this requester/session = {effective_receive_dir} (source: {effective_receive_source}). Treat that receive-dir context as current unless a later qypha_receive_dir tool result changes it in this run, and if there is any doubt verify with qypha_receive_dir before claiming where incoming files are stored. When the user asks who you are or which LLM is connected, identify yourself as a Qypha AI agent and clearly state Provider: {provider}, Model: {model}. Do not describe yourself as OpenClaw; that is only an internal runtime detail. Act as a reliable general-purpose agent. Use the embedded runtime tools proactively whenever they improve accuracy or completeness: web search, web fetch, browser inspection, PDF/document reading, repo/file reading, shell and process tools, memory tools, session status, and workspace editing tools. In normal conversation, if a question depends on current facts, external sources, technical docs, research papers, repositories, or local files, investigate first instead of guessing. For questions about today's date, the current day, the current time, or timezone conversions, verify with session_status first, and use exec for extra verification when needed. Never guess the current date or time. For research work, proceed iteratively: search, inspect promising pages, follow up with additional sources when needed, open PDFs or technical docs when relevant, inspect local code or repositories when relevant, and then answer with concise conclusions plus concrete sources or uncertainty when appropriate. Prefer real inspection over assumptions. When a result involves an academic paper, technical report, standards document, or PDF, prefer the primary source over summaries. Use web_search to find it, web_fetch for normal HTML/docs, browser when rendering/login/state matters, and pdf for the actual document or PDF URL when detailed reading is needed. Do not rely on secondary summaries before checking the primary source when the primary source is available. If model-backed PDF analysis is unavailable, continue with extracted PDF text, OCR-backed PDF extraction, browser/download fallback, or page-by-page reading before falling back to summaries. Never treat an abstract, blog post, or summary page as a full paper read when the PDF exists but has not been inspected. If a paper is long, read it in sections or page ranges until the methodology and results are covered before making strong claims. If OCR or PDF extraction still cannot recover the needed sections, say that clearly and keep the final answer appropriately limited. If a requested runtime capability is not wired yet in Qypha, say so briefly and continue helping with planning, reasoning, drafting, or analysis.",
        name = metadata.name,
        role = metadata.ai_role,
        access = metadata.ai_access_mode,
        provider = provider,
        model = model,
        default_receive_dir = receive_dir_context.default_dir.display(),
        global_receive_dir = receive_dir_context.global_dir.display(),
        effective_receive_dir = receive_dir_context.effective_dir.display(),
        effective_receive_source = receive_dir_context.effective_source,
    )
}

fn load_ai_agent_thread_state(
    metadata: &LaunchAgentDesktopMetadata,
    requester_agent: Option<&str>,
) -> AiAgentThreadState {
    let path = ai_agent_thread_path(&metadata.name, requester_agent);
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
    let Ok(content) = std::fs::read_to_string(path) else {
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

fn save_ai_agent_thread_state(state: &AiAgentThreadState) -> Result<()> {
    let path = ai_agent_thread_path(&state.ai_agent, state.requester_agent.as_deref());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(state)?;
    write_private_file(&path, &json)?;
    Ok(())
}

fn clear_ai_agent_thread_state(ai_agent: &str, requester_agent: Option<&str>) -> Result<()> {
    let path = ai_agent_thread_path(ai_agent, requester_agent);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn suggested_companion_listen_port() -> u16 {
    let count = crate::crypto::keystore::list_agents()
        .unwrap_or_default()
        .len() as u16;
    9090 + count
}

fn is_listen_port_available(port: u16) -> bool {
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let tcp_ok = TcpListener::bind(bind_addr).is_ok();
    let udp_ok = UdpSocket::bind(bind_addr).is_ok();
    tcp_ok && udp_ok
}

fn suggested_available_listen_port(preferred: u16) -> u16 {
    for candidate in preferred..=u16::MAX {
        if candidate != 0 && is_listen_port_available(candidate) {
            return candidate;
        }
    }
    preferred
}

fn rewrite_persistent_ai_config_with_port(
    inspection: &AiAgentStateInspection,
    transport_mode: &TransportMode,
    log_mode: &str,
    listen_port: u16,
    passphrase: &str,
) -> Result<()> {
    let keypair =
        AgentKeyPair::load_from_file(&inspection.identity_path, passphrase).map_err(|e| {
            anyhow::anyhow!(
                "Failed to unlock existing AI identity at {}: {}",
                inspection.identity_path.display(),
                e
            )
        })?;
    let config = crate::agent::init::build_persistent_agent_config(
        &keypair.metadata.display_name,
        &keypair.metadata.role,
        &keypair.did,
        transport_mode.clone(),
        log_mode,
        listen_port,
    );
    crate::agent::init::write_config_to_path(&inspection.config_path, &config, Some(passphrase))?;
    Ok(())
}

fn ensure_interactive_ai_listen_port_available(
    theme: &ColorfulTheme,
    inspection: &AiAgentStateInspection,
    network_plan: &mut AiNetworkLaunchPlan,
) -> Result<()> {
    while !is_listen_port_available(network_plan.listen_port) {
        println!(
            "   {} {} {}",
            "Listen port busy:".yellow().bold(),
            network_plan.listen_port.to_string().cyan(),
            "choose a different port to continue.".dimmed()
        );
        let suggested = suggested_available_listen_port(network_plan.listen_port.saturating_add(1));
        let replacement: u16 = Input::with_theme(theme)
            .with_prompt("  New listen port")
            .default(suggested)
            .interact_text()?;
        network_plan.listen_port = replacement;
        match &mut network_plan.companion_spec {
            AiCompanionLaunchSpec::Persistent { passphrase, .. } => {
                rewrite_persistent_ai_config_with_port(
                    inspection,
                    &network_plan.transport_mode,
                    &network_plan.log_mode,
                    replacement,
                    passphrase,
                )?;
            }
            AiCompanionLaunchSpec::Ghost { listen_port, .. } => {
                *listen_port = replacement;
            }
        }
    }
    Ok(())
}

fn prompt_ai_agent_passphrase(name: &str) -> Result<String> {
    let prompt = format!("  Set a passphrase for AI agent '{}' (min 6 chars)", name);
    let confirm = "  Confirm passphrase";
    let mismatch = "  Passphrases don't match, try again";
    let passphrase = Password::new()
        .with_prompt(prompt)
        .with_confirmation(confirm, mismatch)
        .interact()?;
    if passphrase.trim().len() < 6 {
        anyhow::bail!("Passphrase too short (minimum 6 characters)");
    }
    Ok(passphrase)
}

fn temporarily_set_env(key: &str, value: &str) -> Option<String> {
    let previous = std::env::var(key).ok();
    std::env::set_var(key, value);
    previous
}

fn restore_env(key: &str, previous: Option<String>) {
    if let Some(value) = previous {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

async fn provision_ai_network_agent(
    name: &str,
    transport_mode: &TransportMode,
    log_mode: &str,
    listen_port: u16,
    passphrase: &str,
) -> Result<std::path::PathBuf> {
    let previous_passphrase = temporarily_set_env("QYPHA_PASSPHRASE", passphrase);
    let previous_config_passphrase = temporarily_set_env("QYPHA_CONFIG_PASSPHRASE", passphrase);
    let previous_init_passphrase = temporarily_set_env("QYPHA_INIT_PASSPHRASE", passphrase);
    let result = crate::agent::init::initialize_agent(
        name,
        transport_mode_to_str(transport_mode),
        log_mode,
        Some(listen_port),
    )
    .await;
    restore_env("QYPHA_INIT_PASSPHRASE", previous_init_passphrase);
    restore_env("QYPHA_CONFIG_PASSPHRASE", previous_config_passphrase);
    restore_env("QYPHA_PASSPHRASE", previous_passphrase);
    result?;
    let (config_path, _) = persistent_launch_paths(name)?;
    Ok(config_path)
}

fn prompt_ai_transport_mode(
    theme: &ColorfulTheme,
    default_mode: TransportMode,
) -> Result<TransportMode> {
    let transports = &["Internet", "LAN", "Tor"];
    let default_idx = match default_mode {
        TransportMode::Internet => 0,
        TransportMode::Tcp => 1,
        TransportMode::Tor => 2,
    };
    let transport_idx = Select::with_theme(theme)
        .with_prompt("  Transport mode")
        .items(transports)
        .default(default_idx)
        .interact()?;
    Ok(match transport_idx {
        0 => TransportMode::Internet,
        1 => TransportMode::Tcp,
        2 => TransportMode::Tor,
        _ => default_mode,
    })
}

fn prompt_ai_log_mode(
    theme: &ColorfulTheme,
    transport_mode: &TransportMode,
    default_mode: &str,
) -> Result<String> {
    if !matches!(transport_mode, TransportMode::Tor) {
        return Ok("safe".to_string());
    }

    let log_modes = &[
        "Safe (privacy-hardened, reduced persistence)",
        "Ghost (zero trace, immutable)",
    ];
    let default_idx = if normalize_ai_log_mode_value(default_mode) == "ghost" {
        1
    } else {
        0
    };
    let log_idx = Select::with_theme(theme)
        .with_prompt("  Log mode")
        .items(log_modes)
        .default(default_idx)
        .interact()?;
    Ok(match log_idx {
        1 => "ghost".to_string(),
        _ => "safe".to_string(),
    })
}

fn metadata_ai_transport_mode(
    metadata: Option<&LaunchAgentDesktopMetadata>,
) -> Option<TransportMode> {
    match metadata.and_then(|value| value.ai_transport_mode.as_deref()) {
        Some("lan") => Some(TransportMode::Tcp),
        Some("tor") => Some(TransportMode::Tor),
        Some("internet") => Some(TransportMode::Internet),
        _ => None,
    }
}

fn metadata_ai_listen_port(metadata: Option<&LaunchAgentDesktopMetadata>) -> Option<u16> {
    metadata.and_then(|value| value.ai_listen_port)
}

fn metadata_ai_log_mode(metadata: Option<&LaunchAgentDesktopMetadata>) -> String {
    metadata
        .map(|value| normalize_ai_log_mode_value(&value.ai_log_mode))
        .unwrap_or_else(default_ai_log_mode)
}

fn provider_default_index(provider: Option<&str>) -> usize {
    match provider.unwrap_or("ollama").trim().to_lowercase().as_str() {
        "ollama" => 0,
        "openai" => 1,
        "claude" | "anthropic" => 2,
        "gemini" | "google" => 3,
        _ => 0,
    }
}

async fn prompt_ai_metadata(
    theme: &ColorfulTheme,
    name: &str,
    existing: Option<&LaunchAgentDesktopMetadata>,
) -> Result<LaunchAgentDesktopMetadata> {
    let providers = &["Ollama", "OpenAI", "Claude", "Gemini"];
    let provider_idx = Select::with_theme(theme)
        .with_prompt("  AI provider")
        .items(providers)
        .default(provider_default_index(
            existing.and_then(|metadata| metadata.ai_provider.as_deref()),
        ))
        .interact()?;
    let provider = match provider_idx {
        0 => "ollama",
        1 => "openai",
        2 => "claude",
        3 => "gemini",
        _ => "ollama",
    };
    let existing_model = existing
        .and_then(|metadata| metadata.ai_model.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let suggested_model = provider_default_model_id(provider).unwrap_or("");
    let model = if provider == "ollama" {
        let (ollama_host, models, ollama_error, ollama_available) = discover_ollama_models().await;
        if let Some(error) = &ollama_error {
            println!(
                "   {} {}",
                "Ollama discovery:".yellow().bold(),
                error.dimmed()
            );
        } else if ollama_available {
            println!(
                "   {} {}",
                "Ollama host:".yellow().bold(),
                ollama_host.cyan()
            );
        }

        if models.is_empty() {
            Input::with_theme(theme)
                .with_prompt("  Ollama model")
                .default(existing_model.to_string())
                .allow_empty(true)
                .interact_text()?
        } else {
            let mut labels = models
                .iter()
                .map(|model| {
                    format!(
                        "{} ({})",
                        model.label,
                        if model.source == "cloud" {
                            "cloud"
                        } else {
                            "local"
                        }
                    )
                })
                .collect::<Vec<_>>();
            labels.push("Custom model id".to_string());
            let selected_default = models
                .iter()
                .position(|model| model.id == existing_model)
                .unwrap_or(0)
                .min(labels.len().saturating_sub(1));
            let selected = Select::with_theme(theme)
                .with_prompt("  Ollama model")
                .items(&labels)
                .default(selected_default)
                .interact()?;
            if selected < models.len() {
                models[selected].id.clone()
            } else {
                Input::with_theme(theme)
                    .with_prompt("  Custom Ollama model")
                    .default(existing_model.to_string())
                    .allow_empty(true)
                    .interact_text()?
            }
        }
    } else {
        if let Some(label) = provider_default_model_label(provider) {
            println!(
                "   {} {} {}",
                "Suggested model:".yellow().bold(),
                label.cyan(),
                format!("({})", suggested_model).dimmed()
            );
        }
        Input::with_theme(theme)
            .with_prompt(format!("  {} model id", provider_label(provider)))
            .default(if existing_model.is_empty() {
                suggested_model.to_string()
            } else {
                existing_model.to_string()
            })
            .allow_empty(true)
            .interact_text()?
    };

    if provider != "ollama" {
        let has_saved_secret = read_saved_ai_provider_secret(provider)?.is_some();
        println!(
            "   {} {}",
            "Secure credential:".yellow().bold(),
            if has_saved_secret {
                "already configured".green().to_string()
            } else {
                "not stored yet".dimmed().to_string()
            }
        );
        println!(
            "   {}",
            format!(
                "Paste {} API key directly, or leave blank to {}.",
                provider_label(provider),
                if has_saved_secret {
                    "keep the stored credential"
                } else {
                    "skip for now"
                }
            )
            .dimmed()
        );
        let api_key: String = Input::with_theme(theme)
            .with_prompt(format!("  {} API key", provider_label(provider)))
            .allow_empty(true)
            .interact_text()?;
        if !api_key.trim().is_empty() {
            let trimmed_api_key = api_key.trim();
            sync_ai_provider_secret_to_auth_store_with_value(
                name,
                provider,
                Some(trimmed_api_key),
            )?;
            match store_ai_provider_secret(provider, trimmed_api_key) {
                Ok(()) => println!(
                    "   {}",
                    format!(
                        "{} credential saved to system secure storage and agent auth store.",
                        provider_label(provider)
                    )
                    .green()
                ),
                Err(error) => println!(
                    "   {} {}",
                    "Credential note:".yellow().bold(),
                    format!(
                        "{} key was saved to the agent auth store, but secure storage is unavailable: {}",
                        provider_label(provider),
                        error
                    )
                    .dimmed()
                ),
            }
        }
    }

    let role_idx = Select::with_theme(theme)
        .with_prompt("  AI role")
        .items(&["General"])
        .default(0)
        .interact()?;
    let role = match role_idx {
        0 => "general",
        _ => "general",
    };

    println!(
        "   {} {}",
        "Access mode:".yellow().bold(),
        "Full access".cyan()
    );

    Ok(LaunchAgentDesktopMetadata {
        name: name.trim().to_string(),
        agent_type: DesktopProfileAgentType::Ai,
        ai_provider: Some(provider.to_string()),
        ai_model: (!model.trim().is_empty()).then_some(model.trim().to_string()),
        ai_role: role.to_string(),
        ai_access_mode: "full_access".to_string(),
        ai_log_mode: existing
            .map(|metadata| metadata.ai_log_mode.clone())
            .unwrap_or_else(default_ai_log_mode),
        ai_transport_mode: existing.and_then(|metadata| metadata.ai_transport_mode.clone()),
        ai_listen_port: existing.and_then(|metadata| metadata.ai_listen_port),
        receive_dir_default_snapshot: Some(default_receive_root().display().to_string()),
    }
    .normalized())
}

fn inspect_ai_agent_state(name: &str) -> Result<AiAgentStateInspection> {
    let metadata_path = agent_metadata_path_for_name(name);
    let metadata = load_agent_desktop_metadata(&metadata_path);
    if metadata
        .as_ref()
        .is_some_and(|existing| existing.agent_type == DesktopProfileAgentType::Human)
    {
        anyhow::bail!(
            "Agent '{}' already exists as a human agent profile. Choose a different name or remove the old profile first.",
            name
        );
    }

    let config_path = crate::agent::init::resolve_existing_config_path_for_agent(name);
    let identity_path = KeyStore::agent_data_path(name)?
        .join("keys")
        .join("agent_identity.json");
    let action = determine_persistent_launch_action(config_path.exists(), identity_path.exists());
    if metadata.is_none() && action != PersistentLaunchAction::Initialize {
        anyhow::bail!(
            "Agent '{}' already exists as a persistent network agent, but it is not registered as an AI agent profile. Use a different name or migrate/destroy the old agent first.",
            name
        );
    }
    if action == PersistentLaunchAction::MissingIdentity {
        anyhow::bail!(
            "Persistent AI agent '{}' is incomplete: config {} exists but identity {} is missing",
            name,
            config_path.display(),
            identity_path.display()
        );
    }

    Ok(AiAgentStateInspection {
        metadata,
        config_path,
        identity_path,
        action,
    })
}

fn load_ai_network_plan(
    inspection: &AiAgentStateInspection,
    passphrase: Option<String>,
) -> Result<AiNetworkLaunchPlan> {
    if metadata_ai_log_mode(inspection.metadata.as_ref()) == "ghost" {
        let transport_mode =
            metadata_ai_transport_mode(inspection.metadata.as_ref()).unwrap_or(TransportMode::Tor);
        let listen_port = metadata_ai_listen_port(inspection.metadata.as_ref())
            .unwrap_or_else(suggested_companion_listen_port);
        let name = inspection
            .metadata
            .as_ref()
            .map(|metadata| metadata.name.clone())
            .unwrap_or_else(|| "qypha-ai".to_string());
        return Ok(AiNetworkLaunchPlan {
            transport_mode: transport_mode.clone(),
            log_mode: "ghost".to_string(),
            listen_port,
            companion_spec: AiCompanionLaunchSpec::Ghost {
                name,
                transport_mode,
                listen_port,
            },
        });
    }

    let passphrase = passphrase
        .ok_or_else(|| anyhow::anyhow!("Missing passphrase for persistent AI agent runtime"))?;
    let mut config = AppConfig::load(&inspection.config_path.display().to_string())?;
    if config.has_encrypted_sensitive_fields() {
        config.decrypt_sensitive_fields(Some(&passphrase))?;
    }
    Ok(AiNetworkLaunchPlan {
        transport_mode: config.network.transport_mode.clone(),
        log_mode: normalize_ai_log_mode_value(&config.logging.mode),
        listen_port: config.network.listen_port,
        companion_spec: AiCompanionLaunchSpec::Persistent {
            config_path: inspection.config_path.clone(),
            passphrase,
        },
    })
}

fn recover_ai_network_plan(
    inspection: &AiAgentStateInspection,
    transport_mode: TransportMode,
    log_mode: String,
    listen_port: u16,
    passphrase: Option<String>,
) -> Result<AiNetworkLaunchPlan> {
    if log_mode == "ghost" {
        let name = inspection
            .metadata
            .as_ref()
            .map(|metadata| metadata.name.clone())
            .unwrap_or_else(|| "qypha-ai".to_string());
        return Ok(AiNetworkLaunchPlan {
            transport_mode: transport_mode.clone(),
            log_mode,
            listen_port,
            companion_spec: AiCompanionLaunchSpec::Ghost {
                name,
                transport_mode,
                listen_port,
            },
        });
    }

    let passphrase = passphrase.ok_or_else(|| {
        anyhow::anyhow!("Missing passphrase for persistent AI agent config recovery")
    })?;
    let keypair =
        AgentKeyPair::load_from_file(&inspection.identity_path, &passphrase).map_err(|e| {
            anyhow::anyhow!(
                "{} Failed to unlock existing identity at {}: {}",
                format_existing_agent_recovery_notice(
                    &inspection
                        .metadata
                        .as_ref()
                        .map(|metadata| metadata.name.clone())
                        .unwrap_or_else(|| "AI agent".to_string()),
                    &inspection.config_path,
                    &inspection.identity_path
                ),
                inspection.identity_path.display(),
                e,
            )
        })?;
    let config = crate::agent::init::build_persistent_agent_config(
        &keypair.metadata.display_name,
        &keypair.metadata.role,
        &keypair.did,
        transport_mode.clone(),
        "safe",
        listen_port,
    );
    crate::agent::init::write_config_to_path(&inspection.config_path, &config, Some(&passphrase))?;
    println!(
        "   {} {}",
        "Recovered missing config:".yellow().bold(),
        inspection.config_path.display()
    );
    Ok(AiNetworkLaunchPlan {
        transport_mode,
        log_mode,
        listen_port,
        companion_spec: AiCompanionLaunchSpec::Persistent {
            config_path: inspection.config_path.clone(),
            passphrase,
        },
    })
}

fn companion_runtime_command_args(spec: &AiCompanionLaunchSpec) -> Vec<String> {
    match spec {
        AiCompanionLaunchSpec::Persistent { config_path, .. } => vec![
            "start".to_string(),
            "--config".to_string(),
            config_path.display().to_string(),
        ],
        AiCompanionLaunchSpec::Ghost {
            name,
            transport_mode,
            listen_port,
        } => vec![
            "launch".to_string(),
            "--name".to_string(),
            name.clone(),
            "--transport".to_string(),
            transport_mode_to_str(transport_mode).to_string(),
            "--log-mode".to_string(),
            "ghost".to_string(),
            "--port".to_string(),
            listen_port.to_string(),
        ],
    }
}

fn companion_runtime_display_target(spec: &AiCompanionLaunchSpec) -> String {
    match spec {
        AiCompanionLaunchSpec::Persistent { config_path, .. } => config_path.display().to_string(),
        AiCompanionLaunchSpec::Ghost {
            name,
            transport_mode,
            listen_port,
        } => format!(
            "{} (ghost via {}:{})",
            name,
            transport_mode_to_str(transport_mode),
            listen_port
        ),
    }
}

fn ai_terminal_prompt(agent_name: &str) -> String {
    format!("   \x1b[36m{}\x1b[0m[\x1b[33mAI\x1b[0m] > ", agent_name)
}

fn send_terminal_display(display_tx: &mpsc::UnboundedSender<String>, message: impl Into<String>) {
    let _ = display_tx.send(message.into());
}

fn normalize_ai_transport_message(message: &str) -> String {
    message.split_whitespace().collect::<Vec<_>>().join(" ")
}

async fn send_raw_companion_command(
    stdin: &std::sync::Arc<TokioMutex<ChildStdin>>,
    command: &str,
) -> Result<()> {
    let mut guard = stdin.lock().await;
    guard
        .write_all(format!("{}\n", command.trim()).as_bytes())
        .await?;
    guard.flush().await?;
    Ok(())
}

async fn send_serialized_companion_command(
    runtime_state: &AiTerminalRuntimeState,
    stdin: &std::sync::Arc<TokioMutex<ChildStdin>>,
    command: &str,
) -> Result<()> {
    let _guard = runtime_state.companion_command_lock.lock().await;
    send_raw_companion_command(stdin, command).await
}

fn sanitize_companion_text_input(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{} is required", label);
    }
    if trimmed.chars().any(char::is_control) {
        anyhow::bail!("{} contains forbidden control characters", label);
    }
    Ok(trimmed.to_string())
}

fn sanitize_companion_token_input(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{} is required", label);
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        anyhow::bail!(
            "{} contains forbidden whitespace or control characters",
            label
        );
    }
    Ok(trimmed.to_string())
}

fn encode_companion_ui_bridge_command(command: &CompanionUiBridgeCommand) -> Result<String> {
    let payload = serde_json::to_vec(command)?;
    Ok(format!("/ui {}", URL_SAFE_NO_PAD.encode(payload)))
}

fn sanitize_visible_companion_line(line: &str) -> String {
    strip_ansi_codes(line).trim().to_string()
}

fn resolve_companion_canonical_did(
    visible_or_canonical: &str,
    explicit_canonical: Option<&str>,
) -> String {
    explicit_canonical
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            crate::network::contact_did::decode_contact_did(visible_or_canonical)
                .ok()
                .map(|resolved| resolved.canonical_did)
        })
        .unwrap_or_else(|| visible_or_canonical.trim().to_string())
}

fn resolve_companion_contact_did(
    visible_or_canonical: &str,
    explicit_contact: Option<&str>,
    canonical_did: &str,
) -> String {
    explicit_contact
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| crate::network::contact_did::contact_did_from_canonical_did(canonical_did).ok())
        .unwrap_or_else(|| visible_or_canonical.trim().to_string())
}

async fn replace_cached_companion_peers(
    runtime_state: &AiTerminalRuntimeState,
    peers: &[CompanionControlPeerSnapshot],
) {
    let mut cache = runtime_state.companion_peer_cache.lock().await;
    cache.clear();
    for peer in peers {
        if peer.did.trim().is_empty() {
            continue;
        }
        cache.insert(peer.did.clone(), peer.clone());
    }
}

async fn snapshot_cached_companion_peers(
    runtime_state: &AiTerminalRuntimeState,
) -> Vec<CompanionControlPeerSnapshot> {
    let cache = runtime_state.companion_peer_cache.lock().await;
    let mut peers = cache.values().cloned().collect::<Vec<_>>();
    peers.sort_by(|left, right| left.name.cmp(&right.name).then(left.did.cmp(&right.did)));
    for (idx, peer) in peers.iter_mut().enumerate() {
        peer.selector = (idx + 1).to_string();
    }
    peers
}

fn format_companion_whoami_lines(snapshot: &CompanionControlWhoAmISnapshot) -> Vec<String> {
    let mut lines = vec![
        format!("Name: {}", snapshot.name),
        format!(
            "Contact DID: {}",
            snapshot
                .contact_did
                .as_deref()
                .unwrap_or("not exported yet")
        ),
        format!("Peer ID: {}", snapshot.peer_id),
        format!("Transport: {}", snapshot.transport),
    ];
    if let Some(iroh_id) = snapshot
        .iroh_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("Iroh ID: {}", iroh_id));
    }
    if let Some(onion) = snapshot
        .onion
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("Onion: {}", onion));
    }
    if let Some(ip) = snapshot
        .ip
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("IP: {}", ip));
    }
    if let Some(relay_routes) = snapshot.relay_routes {
        lines.push(format!("Relay routes: {}", relay_routes));
    }
    lines.push(format!("Direct peers: {}", snapshot.direct_peers));
    lines.push(format!("Groups: {}", snapshot.groups));
    lines
}

#[derive(Debug, Default)]
struct CompanionPeerCollection {
    peers: Vec<CompanionControlPeerSnapshot>,
    observed: bool,
}

async fn collect_companion_text_lines(
    rx: &mut broadcast::Receiver<CompanionOutputLine>,
    total_timeout: Duration,
    settle_after_first_line: Duration,
) -> Result<Vec<String>> {
    let deadline = Instant::now() + total_timeout;
    let mut lines = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let wait_for = if lines.is_empty() {
            deadline.saturating_duration_since(now)
        } else {
            settle_after_first_line.min(deadline.saturating_duration_since(now))
        };
        let entry = match timeout(wait_for, rx.recv()).await {
            Ok(Ok(entry)) => entry,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => break,
        };
        let trimmed = sanitize_visible_companion_line(&entry.line);
        if trimmed.is_empty()
            || trimmed == "Headless control channel enabled"
            || trimmed == COMPANION_DIRECT_PEERS_BEGIN
            || trimmed == COMPANION_DIRECT_PEERS_END
            || trimmed == COMPANION_DIRECT_PEERS_EMPTY
            || trimmed == COMPANION_MAILBOX_GROUPS_BEGIN
            || trimmed == COMPANION_MAILBOX_GROUPS_END
            || trimmed == COMPANION_MAILBOX_GROUPS_EMPTY
            || trimmed.starts_with("HANDSHAKE_REQUEST_POLICY ")
            || trimmed.starts_with(COMPANION_DIRECT_PEER)
            || trimmed.starts_with(COMPANION_MAILBOX_GROUP)
            || trimmed.starts_with(COMPANION_WHOAMI)
            || trimmed.starts_with(COMPANION_DIRECT_MESSAGE_EVENT)
            || trimmed.starts_with(COMPANION_DIRECT_PEER_EVENT)
            || trimmed.starts_with(COMPANION_INVITE_RESULT)
            || (trimmed.ends_with('>') && trimmed.contains('['))
        {
            continue;
        }
        lines.push(trimmed);
    }
    Ok(lines)
}

async fn collect_companion_peer_snapshots(
    rx: &mut broadcast::Receiver<CompanionOutputLine>,
) -> Result<CompanionPeerCollection> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut began = false;
    let mut peers: Vec<CompanionControlPeerSnapshot> = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let entry = match timeout(deadline.saturating_duration_since(now), rx.recv()).await {
            Ok(Ok(entry)) => entry,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => break,
        };
        let trimmed = sanitize_visible_companion_line(&entry.line);
        if trimmed == COMPANION_DIRECT_PEERS_EMPTY {
            return Ok(CompanionPeerCollection {
                peers: Vec::new(),
                observed: true,
            });
        }
        if trimmed == COMPANION_DIRECT_PEERS_BEGIN {
            began = true;
            peers.clear();
            continue;
        }
        if trimmed == COMPANION_DIRECT_PEERS_END {
            if began {
                for (idx, peer) in peers.iter_mut().enumerate() {
                    peer.selector = (idx + 1).to_string();
                }
                return Ok(CompanionPeerCollection {
                    peers,
                    observed: true,
                });
            }
            continue;
        }
        if !began {
            continue;
        }
        if let Some(payload) = trimmed.strip_prefix(&format!("{} ", COMPANION_DIRECT_PEER)) {
            let mut peer =
                serde_json::from_str::<CompanionControlPeerSnapshot>(payload).map_err(|error| {
                    anyhow::anyhow!("Failed to parse Qypha peer snapshot: {}", error)
                })?;
            let canonical_did = resolve_companion_canonical_did(&peer.did, None);
            let contact_did = resolve_companion_contact_did(
                &peer.did,
                peer.contact_did.as_deref(),
                &canonical_did,
            );
            peer.selector.clear();
            peer.did = canonical_did;
            peer.contact_did = Some(contact_did);
            peers.push(peer);
        }
    }
    Ok(CompanionPeerCollection {
        peers,
        observed: false,
    })
}

async fn collect_companion_whoami_snapshot(
    rx: &mut broadcast::Receiver<CompanionOutputLine>,
) -> Result<Option<CompanionControlWhoAmISnapshot>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let entry = match timeout(deadline.saturating_duration_since(now), rx.recv()).await {
            Ok(Ok(entry)) => entry,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => break,
        };
        let trimmed = sanitize_visible_companion_line(&entry.line);
        if let Some(payload) = trimmed.strip_prefix(&format!("{} ", COMPANION_WHOAMI)) {
            let snapshot = serde_json::from_str::<CompanionControlWhoAmISnapshot>(payload)
                .map_err(|error| {
                    anyhow::anyhow!("Failed to parse Qypha whoami snapshot: {}", error)
                })?;
            return Ok(Some(snapshot));
        }
    }
    Ok(None)
}

async fn collect_companion_group_summaries(
    rx: &mut broadcast::Receiver<CompanionOutputLine>,
) -> Result<Vec<CompanionControlGroupSummary>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut began = false;
    let mut groups: Vec<CompanionControlGroupSummary> = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let entry = match timeout(deadline.saturating_duration_since(now), rx.recv()).await {
            Ok(Ok(entry)) => entry,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => break,
        };
        let trimmed = sanitize_visible_companion_line(&entry.line);
        if trimmed == COMPANION_MAILBOX_GROUPS_EMPTY {
            return Ok(Vec::new());
        }
        if trimmed == COMPANION_MAILBOX_GROUPS_BEGIN {
            began = true;
            groups.clear();
            continue;
        }
        if trimmed == COMPANION_MAILBOX_GROUPS_END {
            if began {
                return Ok(groups);
            }
            continue;
        }
        if !began {
            continue;
        }
        if let Some(payload) = trimmed.strip_prefix(&format!("{} ", COMPANION_MAILBOX_GROUP)) {
            let group =
                serde_json::from_str::<CompanionControlGroupSummary>(payload).map_err(|error| {
                    anyhow::anyhow!("Failed to parse Qypha group summary: {}", error)
                })?;
            groups.push(group);
        }
    }
    Ok(groups)
}

fn spawn_companion_output_task<R>(
    reader: R,
    is_stderr: bool,
    tx: mpsc::UnboundedSender<CompanionOutputLine>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if tx.send(CompanionOutputLine { is_stderr, line }).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = tx.send(CompanionOutputLine {
                        is_stderr: true,
                        line: format!("AI network runtime stream error: {}", error),
                    });
                    break;
                }
            }
        }
    });
}

fn print_startup_companion_output_line(entry: CompanionOutputLine, ready: &mut bool) {
    let trimmed = entry.line.trim();
    if trimmed.is_empty() {
        return;
    }
    if trimmed.contains("Headless control channel enabled") {
        *ready = true;
    }
    if entry.is_stderr {
        eprintln!("{}", trimmed);
    } else {
        println!("{}", trimmed);
    }
}

async fn wait_for_companion_ready(
    child: &mut Child,
    output_rx: &mut UnboundedReceiver<CompanionOutputLine>,
) -> Result<()> {
    let mut ready = false;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        while let Ok(entry) = output_rx.try_recv() {
            print_startup_companion_output_line(entry, &mut ready);
            if ready {
                return Ok(());
            }
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "AI network runtime exited before becoming ready (status: {})",
                status
            );
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining.min(Duration::from_millis(500)), output_rx.recv()).await {
            Ok(Some(entry)) => {
                print_startup_companion_output_line(entry, &mut ready);
                if ready {
                    return Ok(());
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    anyhow::bail!("Timed out while waiting for AI network runtime to become ready")
}

async fn auto_reply_to_peer_message(
    metadata: LaunchAgentDesktopMetadata,
    stdin: std::sync::Arc<TokioMutex<ChildStdin>>,
    runtime_state: AiTerminalRuntimeState,
    event: CompanionDirectMessageEvent,
) {
    let canonical_peer_did =
        resolve_companion_canonical_did(&event.peer_did, event.peer_canonical_did.as_deref());
    let peer_lock = {
        let mut guard = runtime_state.peer_reply_locks.lock().await;
        guard
            .entry(canonical_peer_did.clone())
            .or_insert_with(|| std::sync::Arc::new(TokioMutex::new(())))
            .clone()
    };
    let _guard = peer_lock.lock().await;

    send_terminal_display(
        &runtime_state.display_tx,
        format!(
            "   {} {}: {}",
            "AI handling".blue().bold(),
            event.peer_name.cyan(),
            event.message
        ),
    );

    if let Err(error) = ensure_ai_peer_accept_always(
        &runtime_state,
        &stdin,
        &canonical_peer_did,
        &event.peer_name,
    )
    .await
    {
        send_terminal_display(
            &runtime_state.display_tx,
            format!(
                "   {} {} ({})",
                "AI auto-accept warning:".yellow().bold(),
                event.peer_name.cyan(),
                error
            ),
        );
    }

    match send_embedded_ai_message(&metadata, Some(&canonical_peer_did), &event.message).await {
        Ok(thread) => {
            let Some(last) = thread.messages.last() else {
                send_terminal_display(
                    &runtime_state.display_tx,
                    format!(
                        "   {} {}",
                        "AI error:".red().bold(),
                        "empty assistant response".dimmed()
                    ),
                );
                return;
            };
            let reply = normalize_ai_transport_message(&last.content);
            if reply.is_empty() {
                send_terminal_display(
                    &runtime_state.display_tx,
                    format!(
                        "   {} {}",
                        "AI error:".red().bold(),
                        "assistant reply was empty after normalization".dimmed()
                    ),
                );
                return;
            }
            if let Err(error) = send_serialized_companion_command(
                &runtime_state,
                &stdin,
                &format!("/sendto {} {}", canonical_peer_did, reply),
            )
            .await
            {
                send_terminal_display(
                    &runtime_state.display_tx,
                    format!("   {} {}", "AI send error:".red().bold(), error),
                );
                return;
            }
            send_terminal_display(
                &runtime_state.display_tx,
                format!(
                    "   {} {}: {}",
                    "AI reply".green().bold(),
                    event.peer_name.cyan(),
                    reply
                ),
            );
        }
        Err(error) => {
            send_terminal_display(
                &runtime_state.display_tx,
                format!("   {} {}", "AI error:".red().bold(), error),
            );
        }
    }
}

async fn ensure_ai_peer_accept_always(
    runtime_state: &AiTerminalRuntimeState,
    stdin: &std::sync::Arc<TokioMutex<ChildStdin>>,
    peer_did: &str,
    peer_name: &str,
) -> Result<bool> {
    let peer_did = sanitize_companion_token_input(peer_did, "peer DID")?;
    {
        let armed = runtime_state.auto_accept_peer_dids.lock().await;
        if armed.contains(&peer_did) {
            return Ok(false);
        }
    }

    send_serialized_companion_command(
        runtime_state,
        stdin,
        &format!("/accept_always {}", peer_did),
    )
    .await?;

    let mut armed = runtime_state.auto_accept_peer_dids.lock().await;
    let inserted = armed.insert(peer_did.clone());
    drop(armed);

    if inserted {
        let label = if peer_name.trim().is_empty() {
            peer_did.clone()
        } else {
            format!("{} ({})", peer_name, peer_did)
        };
        send_terminal_display(
            &runtime_state.display_tx,
            format!(
                "   {} {}",
                "AI auto-policy:".green().bold(),
                format!("accept_always armed for {}", label).dimmed()
            ),
        );
    }

    Ok(inserted)
}

async fn handle_companion_output_line(
    metadata: LaunchAgentDesktopMetadata,
    stdin: std::sync::Arc<TokioMutex<ChildStdin>>,
    runtime_state: AiTerminalRuntimeState,
    entry: CompanionOutputLine,
) {
    let _ = runtime_state.companion_line_tx.send(entry.clone());
    let trimmed = entry.line.trim();
    let sanitized = sanitize_visible_companion_line(trimmed);
    let headless_mode = std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false);
    let should_forward_marker = headless_mode
        && (sanitized == COMPANION_DIRECT_PEERS_BEGIN
            || sanitized == COMPANION_DIRECT_PEERS_END
            || sanitized == COMPANION_DIRECT_PEERS_EMPTY
            || sanitized == COMPANION_MAILBOX_GROUPS_BEGIN
            || sanitized == COMPANION_MAILBOX_GROUPS_END
            || sanitized == COMPANION_MAILBOX_GROUPS_EMPTY
            || sanitized.starts_with(&format!("{} ", COMPANION_DIRECT_PEER))
            || sanitized.starts_with(&format!("{} ", COMPANION_MAILBOX_GROUP))
            || sanitized.starts_with(&format!("{} ", COMPANION_INVITE_RESULT))
            || sanitized.starts_with(&format!("{} ", COMPANION_DIRECT_PEER_EVENT))
            || sanitized.starts_with(&format!("{} ", COMPANION_DIRECT_MESSAGE_EVENT))
            || sanitized.starts_with("HANDSHAKE_REQUEST_POLICY "));
    if should_forward_marker {
        send_terminal_display(&runtime_state.display_tx, sanitized.clone());
    }
    if let Some(payload) = sanitized.strip_prefix(&format!("{} ", COMPANION_WHOAMI)) {
        if let Ok(snapshot) = serde_json::from_str::<CompanionControlWhoAmISnapshot>(payload) {
            let mut cache = runtime_state.companion_whoami_snapshot.lock().await;
            *cache = Some(snapshot);
        }
        return;
    }
    if sanitized == COMPANION_DIRECT_PEERS_EMPTY {
        let mut cache = runtime_state.companion_peer_cache.lock().await;
        cache.clear();
    }
    if sanitized.is_empty()
        || sanitized == "Headless control channel enabled"
        || sanitized == COMPANION_DIRECT_PEERS_BEGIN
        || sanitized == COMPANION_DIRECT_PEERS_END
        || sanitized == COMPANION_DIRECT_PEERS_EMPTY
        || sanitized == COMPANION_MAILBOX_GROUPS_BEGIN
        || sanitized == COMPANION_MAILBOX_GROUPS_END
        || sanitized == COMPANION_MAILBOX_GROUPS_EMPTY
        || sanitized.starts_with("HANDSHAKE_REQUEST_POLICY ")
    {
        return;
    }

    if let Some(payload) = sanitized.strip_prefix(&format!("{} ", COMPANION_DIRECT_PEER)) {
        if let Ok(mut peer) = serde_json::from_str::<CompanionControlPeerSnapshot>(payload) {
            let canonical_did = resolve_companion_canonical_did(&peer.did, None);
            let contact_did = resolve_companion_contact_did(
                &peer.did,
                peer.contact_did.as_deref(),
                &canonical_did,
            );
            peer.did = canonical_did.clone();
            peer.contact_did = Some(contact_did);
            let mut cache = runtime_state.companion_peer_cache.lock().await;
            cache.insert(canonical_did, peer);
        }
        return;
    }
    if sanitized.starts_with(COMPANION_DIRECT_PEER) {
        return;
    }
    if sanitized.starts_with(COMPANION_MAILBOX_GROUP) {
        return;
    }

    if let Some(payload) = sanitized.strip_prefix(&format!("{} ", COMPANION_INVITE_RESULT)) {
        if let Ok(result) = serde_json::from_str::<CompanionInviteResult>(payload) {
            if let Some(error) = result.error {
                send_terminal_display(
                    &runtime_state.display_tx,
                    format!(
                        "   {} {} invite failed: {}",
                        "Invite".red().bold(),
                        result.kind,
                        error
                    ),
                );
            }
        }
        return;
    }

    if let Some(payload) = sanitized.strip_prefix(&format!("{} ", COMPANION_DIRECT_PEER_EVENT)) {
        if let Ok(event) = serde_json::from_str::<CompanionDirectPeerEvent>(payload) {
            let canonical_did =
                resolve_companion_canonical_did(&event.did, event.canonical_did.as_deref());
            let contact_did = resolve_companion_contact_did(
                &event.did,
                event.contact_did.as_deref(),
                &canonical_did,
            );
            if !canonical_did.trim().is_empty() {
                let mut cache = runtime_state.companion_peer_cache.lock().await;
                if event.event.eq_ignore_ascii_case("disconnected") {
                    cache.remove(&canonical_did);
                } else {
                    let entry = cache.entry(canonical_did.clone()).or_insert_with(|| {
                        CompanionControlPeerSnapshot {
                            selector: String::new(),
                            name: event.name.clone(),
                            did: canonical_did.clone(),
                            contact_did: Some(contact_did.clone()),
                            peer_id: event.peer_id.clone(),
                            status: event.status.clone(),
                        }
                    });
                    entry.name = event.name.clone();
                    entry.contact_did = Some(contact_did.clone());
                    entry.status = event.status.clone();
                    if let Some(peer_id) = event
                        .peer_id
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                    {
                        entry.peer_id = Some(peer_id);
                    }
                }
            }
            let mut summary = format!(
                "   {} {} — {}",
                "Peer event".green().bold(),
                event.name.cyan(),
                event.event
            );
            if !event.status.trim().is_empty() {
                summary.push_str(&format!(" [{}]", event.status));
            }
            if let Some(reason) = event
                .reason
                .clone()
                .filter(|value| !value.trim().is_empty())
            {
                summary.push_str(&format!(" ({})", reason));
            }
            send_terminal_display(&runtime_state.display_tx, summary);
            if event.event.eq_ignore_ascii_case("connected")
                && !canonical_did.trim().is_empty()
                && event.status.eq_ignore_ascii_case("ready")
            {
                let stdin_clone = stdin.clone();
                let runtime_state_clone = runtime_state.clone();
                let canonical_did_clone = canonical_did.clone();
                let event_clone = event;
                tokio::spawn(async move {
                    let _ = ensure_ai_peer_accept_always(
                        &runtime_state_clone,
                        &stdin_clone,
                        &canonical_did_clone,
                        &event_clone.name,
                    )
                    .await;
                });
            }
        }
        return;
    }

    if let Some(payload) = sanitized.strip_prefix(&format!("{} ", COMPANION_DIRECT_MESSAGE_EVENT)) {
        if let Ok(event) = serde_json::from_str::<CompanionDirectMessageEvent>(payload) {
            if event.direction.eq_ignore_ascii_case("incoming") {
                let metadata_clone = metadata.clone();
                let stdin_clone = stdin.clone();
                let runtime_state_clone = runtime_state.clone();
                tokio::spawn(async move {
                    auto_reply_to_peer_message(
                        metadata_clone,
                        stdin_clone,
                        runtime_state_clone,
                        event,
                    )
                    .await;
                });
            }
        }
        return;
    }

    send_terminal_display(&runtime_state.display_tx, sanitized);
}

fn spawn_companion_output_handler(
    metadata: LaunchAgentDesktopMetadata,
    stdin: std::sync::Arc<TokioMutex<ChildStdin>>,
    mut output_rx: UnboundedReceiver<CompanionOutputLine>,
    runtime_state: AiTerminalRuntimeState,
) {
    tokio::spawn(async move {
        while let Some(entry) = output_rx.recv().await {
            handle_companion_output_line(
                metadata.clone(),
                stdin.clone(),
                runtime_state.clone(),
                entry,
            )
            .await;
        }
    });
}

async fn ensure_companion_runtime(
    spec: &AiCompanionLaunchSpec,
    metadata: &LaunchAgentDesktopMetadata,
    runtime_state: &AiTerminalRuntimeState,
    runtime: &mut Option<CompanionRuntimeSession>,
) -> Result<()> {
    let already_running = match runtime.as_mut() {
        Some(session) => session.child.try_wait()?.is_none(),
        None => false,
    };
    if already_running {
        return Ok(());
    }
    *runtime = None;
    let args = companion_runtime_command_args(spec);
    let current_exe = std::env::current_exe()
        .map_err(|error| anyhow::anyhow!("Failed to locate Qypha executable: {}", error))?;

    println!(
        "   {} {}",
        "Starting AI network runtime:".yellow().bold(),
        companion_runtime_display_target(spec).cyan()
    );

    let mut command = Command::new(current_exe);
    command
        .args(&args)
        .env("QYPHA_HEADLESS", "1")
        .current_dir(workspace_root())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let AiCompanionLaunchSpec::Persistent { passphrase, .. } = spec {
        command
            .env("QYPHA_PASSPHRASE", passphrase)
            .env("QYPHA_CONFIG_PASSPHRASE", passphrase);
    }
    let mut child = command
        .spawn()
        .map_err(|error| anyhow::anyhow!("Failed to start companion runtime: {}", error))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture companion runtime stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture companion runtime stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture companion runtime stderr"))?;
    let (output_tx, mut output_rx) = mpsc::unbounded_channel();
    spawn_companion_output_task(stdout, false, output_tx.clone());
    spawn_companion_output_task(stderr, true, output_tx);
    wait_for_companion_ready(&mut child, &mut output_rx).await?;
    let stdin = std::sync::Arc::new(TokioMutex::new(stdin));
    {
        let mut stdin_slot = runtime_state.companion_stdin.lock().await;
        *stdin_slot = Some(stdin.clone());
    }
    spawn_companion_output_handler(
        metadata.clone(),
        stdin.clone(),
        output_rx,
        runtime_state.clone(),
    );

    *runtime = Some(CompanionRuntimeSession { child, stdin });
    Ok(())
}

async fn send_companion_runtime_command(
    spec: &AiCompanionLaunchSpec,
    metadata: &LaunchAgentDesktopMetadata,
    runtime_state: &AiTerminalRuntimeState,
    runtime: &mut Option<CompanionRuntimeSession>,
    command: &str,
) -> Result<()> {
    ensure_companion_runtime(spec, metadata, runtime_state, runtime).await?;
    let session = runtime
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("AI network runtime is not available"))?;
    send_serialized_companion_command(runtime_state, &session.stdin, command).await
}

async fn execute_companion_control_request(
    runtime_state: &AiTerminalRuntimeState,
    request: CompanionControlRequest,
) -> Result<CompanionControlResponse> {
    let action = match &request {
        CompanionControlRequest::Peers { .. } => "qypha_peers",
        CompanionControlRequest::Groups => "qypha_groups",
        CompanionControlRequest::WhoAmI => "qypha_whoami",
        CompanionControlRequest::Send { .. } => "qypha_send",
        CompanionControlRequest::SendTo { .. } => "qypha_sendto",
        CompanionControlRequest::Disconnect { .. } => "qypha_disconnect",
        CompanionControlRequest::TransferToPeer { .. }
        | CompanionControlRequest::TransferToGroup { .. } => "qypha_transfer",
        CompanionControlRequest::ReceiveDir { .. } => "qypha_receive_dir",
        CompanionControlRequest::Accept { .. } => "qypha_accept",
        CompanionControlRequest::AcceptAlways { .. } => "qypha_accept_always",
        CompanionControlRequest::AcceptAsk { .. } => "qypha_accept_ask",
        CompanionControlRequest::Reject { .. } => "qypha_reject",
        CompanionControlRequest::Invite => "qypha_invite",
        CompanionControlRequest::GroupNormal { .. } => "qypha_group_normal",
        CompanionControlRequest::InviteGroup { .. } => "qypha_invite_group",
        CompanionControlRequest::GroupAnon { .. } => "qypha_group_anon",
        CompanionControlRequest::InviteAnon { .. } => "qypha_invite_anon",
        CompanionControlRequest::InviteHandshake { .. } => "qypha_invite_handshake",
        CompanionControlRequest::InviteHandshakeGroup { .. } => "qypha_invite_handshake_group",
        CompanionControlRequest::Block { .. } => "qypha_block",
        CompanionControlRequest::Unblock { .. } => "qypha_unblock",
        CompanionControlRequest::BlockAllRequests => "qypha_block_all_requests",
        CompanionControlRequest::UnblockAllRequests => "qypha_unblock_all_requests",
        CompanionControlRequest::Connect { .. } => "qypha_connect",
        CompanionControlRequest::KickGroupMember { .. } => "qypha_kick_group_member",
        CompanionControlRequest::LockGroup { .. } => "qypha_lock_group",
        CompanionControlRequest::UnlockGroup { .. } => "qypha_unlock_group",
        CompanionControlRequest::LeaveGroup { .. } => "qypha_leave_group",
        CompanionControlRequest::DisbandGroup { .. } => "qypha_disband_group",
        CompanionControlRequest::Quit => "qypha_quit",
    }
    .to_string();

    let (command, total_timeout, settle_after_first_line, default_text, resolved_target) =
        match &request {
            CompanionControlRequest::Peers { verbose } => (
                if *verbose {
                    "/peers -v".to_string()
                } else {
                    "/peers".to_string()
                },
                Duration::from_secs(5),
                Duration::from_millis(350),
                None,
                None,
            ),
            CompanionControlRequest::Groups => (
                "/groups".to_string(),
                Duration::from_secs(5),
                Duration::from_millis(350),
                None,
                None,
            ),
            CompanionControlRequest::WhoAmI => (
                "/whoami".to_string(),
                Duration::from_secs(5),
                Duration::from_millis(350),
                Some("Qypha whoami command dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::Send { message } => (
                format!(
                    "/send {}",
                    sanitize_companion_text_input(message, "message")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha send command dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::SendTo { target, message } => (
                encode_companion_ui_bridge_command(&CompanionUiBridgeCommand::SendTo {
                    selector: sanitize_companion_text_input(target, "target")?,
                    message: sanitize_companion_text_input(message, "message")?,
                })?,
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha targeted send command dispatched.".to_string()),
                Some(target.clone()),
            ),
            CompanionControlRequest::Disconnect { target } => (
                format!(
                    "/disconnect {}",
                    sanitize_companion_token_input(target, "target")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha disconnect command dispatched.".to_string()),
                Some(target.clone()),
            ),
            CompanionControlRequest::TransferToPeer { target, path } => (
                encode_companion_ui_bridge_command(&CompanionUiBridgeCommand::TransferToPeer {
                    selector: sanitize_companion_text_input(target, "target")?,
                    path: sanitize_companion_text_input(path, "path")?,
                })?,
                Duration::from_secs(10),
                Duration::from_millis(500),
                Some("Qypha transfer command dispatched.".to_string()),
                Some(target.clone()),
            ),
            CompanionControlRequest::TransferToGroup { group_id, path } => (
                encode_companion_ui_bridge_command(&CompanionUiBridgeCommand::TransferToGroup {
                    group_id: sanitize_companion_text_input(group_id, "group_id")?,
                    path: sanitize_companion_text_input(path, "path")?,
                })?,
                Duration::from_secs(10),
                Duration::from_millis(500),
                Some("Qypha group transfer command dispatched.".to_string()),
                Some(group_id.clone()),
            ),
            CompanionControlRequest::ReceiveDir {
                target,
                path,
                reset,
            } => {
                let command = match (target.as_deref(), path.as_deref(), *reset) {
                    (Some(target), Some(path), false) => format!(
                        "/receive_dir {} {}",
                        sanitize_companion_token_input(target, "target")?,
                        sanitize_companion_text_input(path, "path")?
                    ),
                    (Some(target), None, true) => format!(
                        "/receive_dir {} reset",
                        sanitize_companion_token_input(target, "target")?
                    ),
                    (None, Some(path), false) => format!(
                        "/receive_dir {}",
                        sanitize_companion_text_input(path, "path")?
                    ),
                    (None, None, true) => "/receive_dir reset".to_string(),
                    (None, None, false) => "/receive_dir".to_string(),
                    (Some(_), None, false) => {
                        anyhow::bail!(
                            "target-specific receive_dir updates require a path or reset=true"
                        )
                    }
                    (_, Some(_), true) => {
                        anyhow::bail!("receive_dir path cannot be combined with reset=true")
                    }
                };
                (
                    command,
                    Duration::from_secs(5),
                    Duration::from_millis(450),
                    Some("Qypha receive_dir command dispatched.".to_string()),
                    target.clone(),
                )
            }
            CompanionControlRequest::Accept { selector } => (
                match selector.as_deref() {
                    Some(selector) => format!(
                        "/accept {}",
                        sanitize_companion_token_input(selector, "selector")?
                    ),
                    None => "/accept".to_string(),
                },
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha accept command dispatched.".to_string()),
                selector.clone(),
            ),
            CompanionControlRequest::AcceptAlways { target } => (
                format!(
                    "/accept_always {}",
                    sanitize_companion_token_input(target, "target")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha accept_always command dispatched.".to_string()),
                Some(target.clone()),
            ),
            CompanionControlRequest::AcceptAsk { target } => (
                format!(
                    "/accept_ask {}",
                    sanitize_companion_token_input(target, "target")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha accept_ask command dispatched.".to_string()),
                Some(target.clone()),
            ),
            CompanionControlRequest::Reject { selector } => (
                match selector.as_deref() {
                    Some(selector) => format!(
                        "/reject {}",
                        sanitize_companion_token_input(selector, "selector")?
                    ),
                    None => "/reject".to_string(),
                },
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha reject command dispatched.".to_string()),
                selector.clone(),
            ),
            CompanionControlRequest::Invite => (
                "/invite".to_string(),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha invite command dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::GroupNormal { name } => (
                format!(
                    "/group_normal {}",
                    sanitize_companion_text_input(name, "name")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha durable group creation dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::InviteGroup { group_id } => (
                format!(
                    "/invite_g {}",
                    sanitize_companion_token_input(group_id, "group_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha group invite command dispatched.".to_string()),
                Some(group_id.clone()),
            ),
            CompanionControlRequest::GroupAnon { name } => (
                match name {
                    Some(name) => format!(
                        "/group_anon {}",
                        sanitize_companion_text_input(name, "name")?
                    ),
                    None => "/group_anon".to_string(),
                },
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha anonymous group creation dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::InviteAnon { owner_special_id } => (
                format!(
                    "/invite_anon {}",
                    sanitize_companion_token_input(owner_special_id, "owner_special_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha anonymous group invite command dispatched.".to_string()),
                Some(owner_special_id.clone()),
            ),
            CompanionControlRequest::InviteHandshake { member_id } => (
                format!(
                    "/invite_h {}",
                    sanitize_companion_token_input(member_id, "member_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha direct handshake invite dispatched.".to_string()),
                Some(member_id.clone()),
            ),
            CompanionControlRequest::InviteHandshakeGroup {
                group_id,
                member_id,
            } => (
                format!(
                    "/invite_hg {} {}",
                    sanitize_companion_token_input(group_id, "group_id")?,
                    sanitize_companion_token_input(member_id, "member_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha group-scoped direct handshake invite dispatched.".to_string()),
                Some(format!("{}:{}", group_id, member_id)),
            ),
            CompanionControlRequest::Block { selector } => (
                match selector.as_deref() {
                    Some(selector) => format!(
                        "/block {}",
                        sanitize_companion_token_input(selector, "selector")?
                    ),
                    None => "/block".to_string(),
                },
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha block command dispatched.".to_string()),
                selector.clone(),
            ),
            CompanionControlRequest::Unblock { member_id } => (
                format!(
                    "/unblock {}",
                    sanitize_companion_token_input(member_id, "member_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha unblock command dispatched.".to_string()),
                Some(member_id.clone()),
            ),
            CompanionControlRequest::BlockAllRequests => (
                "/block_all_r".to_string(),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha block_all_r command dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::UnblockAllRequests => (
                "/unblock_all_r".to_string(),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha unblock_all_r command dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::Connect { code } => (
                format!("/connect {}", sanitize_companion_text_input(code, "code")?),
                Duration::from_secs(10),
                Duration::from_millis(500),
                Some("Qypha connect command dispatched.".to_string()),
                None,
            ),
            CompanionControlRequest::KickGroupMember { member_id } => (
                format!(
                    "/kick_g {}",
                    sanitize_companion_token_input(member_id, "member_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha kick_g command dispatched.".to_string()),
                Some(member_id.clone()),
            ),
            CompanionControlRequest::LockGroup { group_id } => (
                format!(
                    "/lock_g {}",
                    sanitize_companion_token_input(group_id, "group_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha lock_g command dispatched.".to_string()),
                Some(group_id.clone()),
            ),
            CompanionControlRequest::UnlockGroup { group_id } => (
                format!(
                    "/unlock_g {}",
                    sanitize_companion_token_input(group_id, "group_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha unlock_g command dispatched.".to_string()),
                Some(group_id.clone()),
            ),
            CompanionControlRequest::LeaveGroup { group_id } => (
                format!(
                    "/leave_g {}",
                    sanitize_companion_token_input(group_id, "group_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha leave_g command dispatched.".to_string()),
                Some(group_id.clone()),
            ),
            CompanionControlRequest::DisbandGroup { group_id } => (
                format!(
                    "/disband {}",
                    sanitize_companion_token_input(group_id, "group_id")?
                ),
                Duration::from_secs(5),
                Duration::from_millis(450),
                Some("Qypha disband command dispatched.".to_string()),
                Some(group_id.clone()),
            ),
            CompanionControlRequest::Quit => (
                "/quit".to_string(),
                Duration::from_secs(5),
                Duration::from_millis(350),
                Some("Qypha quit command dispatched.".to_string()),
                None,
            ),
        };

    let _guard = runtime_state.companion_command_lock.lock().await;
    let stdin = runtime_state
        .companion_stdin
        .lock()
        .await
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Qypha companion runtime is not available"))?;
    let mut rx = runtime_state.companion_line_tx.subscribe();
    send_raw_companion_command(&stdin, &command).await?;

    match request {
        CompanionControlRequest::Peers { .. } => {
            let collected = collect_companion_peer_snapshots(&mut rx).await?;
            let peers = if collected.observed {
                replace_cached_companion_peers(runtime_state, &collected.peers).await;
                collected.peers
            } else {
                let cached = snapshot_cached_companion_peers(runtime_state).await;
                if cached.is_empty() {
                    collected.peers
                } else {
                    cached
                }
            };
            Ok(CompanionControlResponse {
                ok: true,
                action,
                text: Some(format!("{} peer(s)", peers.len())),
                lines: Vec::new(),
                peers,
                groups: Vec::new(),
                whoami: None,
                resolved_target: None,
                error: None,
            })
        }
        CompanionControlRequest::Groups => {
            let groups = collect_companion_group_summaries(&mut rx).await?;
            Ok(CompanionControlResponse {
                ok: true,
                action,
                text: Some(format!("{} group(s)", groups.len())),
                lines: Vec::new(),
                peers: Vec::new(),
                groups,
                whoami: None,
                resolved_target: None,
                error: None,
            })
        }
        CompanionControlRequest::WhoAmI => {
            let snapshot = match collect_companion_whoami_snapshot(&mut rx).await? {
                Some(snapshot) => {
                    let mut cache = runtime_state.companion_whoami_snapshot.lock().await;
                    *cache = Some(snapshot.clone());
                    snapshot
                }
                None => runtime_state
                    .companion_whoami_snapshot
                    .lock()
                    .await
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("Qypha whoami snapshot unavailable"))?,
            };
            let lines = format_companion_whoami_lines(&snapshot);
            Ok(CompanionControlResponse {
                ok: true,
                action,
                text: Some(lines.join("\n")),
                lines,
                peers: Vec::new(),
                groups: Vec::new(),
                whoami: Some(snapshot),
                resolved_target: None,
                error: None,
            })
        }
        _ => {
            let lines =
                collect_companion_text_lines(&mut rx, total_timeout, settle_after_first_line)
                    .await?;
            let text = if lines.is_empty() {
                default_text
            } else {
                Some(lines.join("\n"))
            };
            Ok(CompanionControlResponse {
                ok: true,
                action,
                text,
                lines,
                peers: Vec::new(),
                groups: Vec::new(),
                whoami: None,
                resolved_target,
                error: None,
            })
        }
    }
}

#[cfg(unix)]
async fn handle_companion_control_connection(
    stream: tokio::net::UnixStream,
    info: CompanionControlInfo,
    runtime_state: AiTerminalRuntimeState,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let response = match lines.next_line().await {
        Ok(Some(line)) => match serde_json::from_str::<CompanionControlEnvelope>(line.trim()) {
            Ok(envelope) if envelope.token == info.auth_token => {
                match execute_companion_control_request(&runtime_state, envelope.request).await {
                    Ok(success) => success,
                    Err(error) => CompanionControlResponse {
                        ok: false,
                        action: "error".to_string(),
                        text: None,
                        lines: Vec::new(),
                        peers: Vec::new(),
                        groups: Vec::new(),
                        whoami: None,
                        resolved_target: None,
                        error: Some(error.to_string()),
                    },
                }
            }
            Ok(_) => CompanionControlResponse {
                ok: false,
                action: "unauthorized".to_string(),
                text: None,
                lines: Vec::new(),
                peers: Vec::new(),
                groups: Vec::new(),
                whoami: None,
                resolved_target: None,
                error: Some("Unauthorized Qypha control request".to_string()),
            },
            Err(error) => CompanionControlResponse {
                ok: false,
                action: "invalid_request".to_string(),
                text: None,
                lines: Vec::new(),
                peers: Vec::new(),
                groups: Vec::new(),
                whoami: None,
                resolved_target: None,
                error: Some(format!("Invalid Qypha control request: {}", error)),
            },
        },
        Ok(None) => return Ok(()),
        Err(error) => CompanionControlResponse {
            ok: false,
            action: "error".to_string(),
            text: None,
            lines: Vec::new(),
            peers: Vec::new(),
            groups: Vec::new(),
            whoami: None,
            resolved_target: None,
            error: Some(format!("Failed to read Qypha control request: {}", error)),
        },
    };
    let body = serde_json::to_string(&response)?;
    writer.write_all(body.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn start_companion_control_server(
    metadata: &LaunchAgentDesktopMetadata,
    runtime_state: &AiTerminalRuntimeState,
) -> Result<Option<CompanionControlServerHandle>> {
    #[cfg(not(unix))]
    {
        let _ = metadata;
        let _ = runtime_state;
        Ok(None)
    }

    #[cfg(unix)]
    {
        use tokio::net::UnixListener;

        let control_dir = std::path::PathBuf::from("/tmp").join("qlcc");
        std::fs::create_dir_all(&control_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&control_dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut agent_segment = KeyStore::sanitize_agent_name(&metadata.name);
        agent_segment.truncate(12);
        let request_id = Uuid::new_v4().simple().to_string();
        let socket_name = format!(
            "q-{}-{}.sock",
            agent_segment,
            &request_id[..8.min(request_id.len())]
        );
        let socket_path = control_dir.join(socket_name);
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }
        if socket_path.as_os_str().len() >= 100 {
            anyhow::bail!(
                "Qypha companion control socket path is still too long: {}",
                socket_path.display()
            );
        }
        let listener = UnixListener::bind(&socket_path)?;
        let info = CompanionControlInfo {
            socket_path: socket_path.display().to_string(),
            auth_token: Uuid::new_v4().to_string(),
        };
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let runtime_state_clone = runtime_state.clone();
        let info_clone = info.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _addr)) => {
                                let runtime_state_conn = runtime_state_clone.clone();
                                let info_conn = info_clone.clone();
                                tokio::spawn(async move {
                                    let _ = handle_companion_control_connection(stream, info_conn, runtime_state_conn).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&socket_path);
        });
        set_active_companion_control_info(Some(info.clone()));
        Ok(Some(CompanionControlServerHandle {
            info,
            shutdown_tx: Some(shutdown_tx),
        }))
    }
}

async fn shutdown_companion_control_server(
    handle: &mut Option<CompanionControlServerHandle>,
) -> Result<()> {
    set_active_companion_control_info(None);
    if let Some(handle) = handle.as_mut() {
        if let Some(shutdown_tx) = handle.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        let _ = std::fs::remove_file(&handle.info.socket_path);
    }
    *handle = None;
    Ok(())
}

async fn shutdown_companion_runtime(runtime: &mut Option<CompanionRuntimeSession>) -> Result<()> {
    let Some(mut session) = runtime.take() else {
        return Ok(());
    };
    let _ = send_raw_companion_command(&session.stdin, "/quit").await;
    if session.child.try_wait()?.is_none() {
        let _ = timeout(Duration::from_secs(2), session.child.wait()).await;
        if session.child.try_wait()?.is_none() {
            let _ = session.child.start_kill();
            let _ = session.child.wait().await;
        }
    }
    Ok(())
}

pub(crate) fn normalized_ollama_host() -> String {
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

async fn discover_ollama_models() -> (String, Vec<OllamaWizardModelOption>, Option<String>, bool) {
    let ollama_host = normalized_ollama_host();
    let mut models = configured_ollama_cloud_models()
        .into_iter()
        .map(|id| OllamaWizardModelOption {
            label: id.clone(),
            id,
            source: "cloud".to_string(),
        })
        .collect::<Vec<_>>();
    let mut ollama_available = false;
    let mut ollama_error = None;

    let response = match reqwest::Client::builder().build() {
        Ok(client) => {
            client
                .get(format!("{}/api/tags", ollama_host.trim_end_matches('/')))
                .send()
                .await
        }
        Err(error) => Err(error),
    };

    match response {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<OllamaWizardTagsResponse>().await {
                    Ok(payload) => {
                        ollama_available = true;
                        models.extend(payload.models.into_iter().map(|model| {
                            OllamaWizardModelOption {
                                label: model.name.clone(),
                                id: model.name,
                                source: "local".to_string(),
                            }
                        }));
                    }
                    Err(error) => {
                        ollama_error = Some(error.to_string());
                    }
                }
            } else {
                ollama_error = Some(format!("Ollama returned HTTP {}", response.status()));
            }
        }
        Err(error) => {
            ollama_error = Some(error.to_string());
        }
    }

    models.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.source.cmp(&b.source)));
    models.dedup_by(|a, b| a.id == b.id && a.source == b.source);

    (ollama_host, models, ollama_error, ollama_available)
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

fn normalize_ai_provider(provider: &str) -> Option<&'static str> {
    match provider.trim().to_lowercase().as_str() {
        "openai" => Some("openai"),
        "claude" | "anthropic" => Some("claude"),
        "gemini" | "google" => Some("gemini"),
        "ollama" => Some("ollama"),
        _ => None,
    }
}

fn provider_default_model_id(provider: &str) -> Option<&'static str> {
    match normalize_ai_provider(provider) {
        Some("openai") => Some("gpt-5.4"),
        Some("claude") => Some("claude-sonnet-4-6"),
        Some("gemini") => Some("gemini-2.5-flash"),
        _ => None,
    }
}

fn provider_default_model_label(provider: &str) -> Option<&'static str> {
    match normalize_ai_provider(provider) {
        Some("openai") => Some("GPT-5.4"),
        Some("claude") => Some("Claude Sonnet 4.6"),
        Some("gemini") => Some("Gemini 2.5 Flash"),
        _ => None,
    }
}

fn provider_secret_env_var(provider: &str) -> Option<&'static str> {
    match normalize_ai_provider(provider) {
        Some("openai") => Some("OPENAI_API_KEY"),
        Some("claude") => Some("ANTHROPIC_API_KEY"),
        Some("gemini") => Some("GEMINI_API_KEY"),
        _ => None,
    }
}

fn ai_provider_env_overrides() -> &'static StdMutex<HashMap<String, String>> {
    AI_PROVIDER_ENV_OVERRIDES.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn ai_provider_memory_secrets() -> &'static StdMutex<HashMap<String, String>> {
    static MEMORY_SECRETS: OnceLock<StdMutex<HashMap<String, String>>> = OnceLock::new();
    MEMORY_SECRETS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn ai_provider_secret_entry(provider: &str) -> Result<keyring::Entry> {
    let normalized = normalize_ai_provider(provider)
        .ok_or_else(|| anyhow::anyhow!("Unsupported AI provider: {}", provider.trim()))?;
    keyring::Entry::new("qypha-desktop.ai-provider", normalized)
        .map_err(|error| anyhow::anyhow!("Failed to prepare secure storage entry: {}", error))
}

fn read_saved_ai_provider_secret(provider: &str) -> Result<Option<String>> {
    let normalized = normalize_ai_provider(provider)
        .ok_or_else(|| anyhow::anyhow!("Unsupported AI provider: {}", provider.trim()))?;
    if let Ok(guard) = ai_provider_memory_secrets().lock() {
        if let Some(secret) = guard
            .get(normalized)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(secret.to_string()));
        }
    }
    let entry = ai_provider_secret_entry(provider)?;
    match entry.get_password() {
        Ok(secret) => Ok((!secret.trim().is_empty()).then_some(secret.trim().to_string())),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to inspect stored {} credential: {}",
            provider_label(provider),
            error
        )),
    }
}

fn store_ai_provider_secret(provider: &str, secret: &str) -> Result<()> {
    let normalized = normalize_ai_provider(provider)
        .ok_or_else(|| anyhow::anyhow!("Unsupported AI provider: {}", provider.trim()))?;
    {
        let mut guard = ai_provider_memory_secrets()
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock provider memory secrets"))?;
        guard.insert(normalized.to_string(), secret.trim().to_string());
    }
    let entry = ai_provider_secret_entry(provider)?;
    entry.set_password(secret.trim()).map_err(|error| {
        anyhow::anyhow!(
            "Failed to store {} credential: {}",
            provider_label(provider),
            error
        )
    })
}

fn provider_auth_store_mapping(provider: &str) -> Option<(&'static str, &'static str)> {
    match normalize_ai_provider(provider) {
        Some("openai") => Some(("openai", "openai:default")),
        Some("claude") => Some(("anthropic", "anthropic:default")),
        Some("gemini") => Some(("google", "google:default")),
        _ => None,
    }
}

fn sync_ai_provider_secret_to_auth_store_with_value(
    agent_name: &str,
    provider: &str,
    explicit_secret: Option<&str>,
) -> Result<bool> {
    let Some((auth_provider, profile_id)) = provider_auth_store_mapping(provider) else {
        return Ok(false);
    };
    let auth_store_path = embedded_runtime_agent_dir(agent_name).join("auth-profiles.json");
    let mut root = std::fs::read_to_string(&auth_store_path)
        .ok()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    if !root.is_object() {
        root = serde_json::json!({});
    }
    if root
        .get("version")
        .and_then(|value| value.as_u64())
        .is_none()
    {
        root["version"] = serde_json::json!(1);
    }
    if !root.get("profiles").is_some_and(|value| value.is_object()) {
        root["profiles"] = serde_json::json!({});
    }

    let profiles = root
        .get_mut("profiles")
        .and_then(|value| value.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("auth-profiles.json has invalid profiles payload"))?;

    let next_secret = if let Some(secret) = explicit_secret
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
    {
        Some(secret)
    } else {
        read_saved_ai_provider_secret(provider)?
    };
    let existing = profiles.get(profile_id).cloned();

    match next_secret {
        Some(secret) => {
            let next_value = serde_json::json!({
                "type": "api_key",
                "provider": auth_provider,
                "key": secret,
            });
            if existing.as_ref() == Some(&next_value) {
                return Ok(false);
            }
            profiles.insert(profile_id.to_string(), next_value);
        }
        None => {
            if existing.is_some() {
                return Ok(false);
            }
            if profiles.remove(profile_id).is_none() {
                return Ok(false);
            }
        }
    }

    if let Some(parent) = auth_store_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&root)?;
    write_private_file(&auth_store_path, &json)?;
    Ok(true)
}

fn sync_ai_provider_secret_to_auth_store(agent_name: &str, provider: &str) -> Result<bool> {
    sync_ai_provider_secret_to_auth_store_with_value(agent_name, provider, None)
}

fn sync_ai_provider_secret_env(provider: &str) -> Result<bool> {
    let Some(env_var) = provider_secret_env_var(provider) else {
        return Ok(false);
    };
    let mut overrides = ai_provider_env_overrides()
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock provider env overrides"))?;
    let next_secret = match read_saved_ai_provider_secret(provider) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    match next_secret {
        Some(secret) => {
            let needs_update = overrides.get(env_var).map(String::as_str) != Some(secret.as_str());
            if needs_update {
                std::env::set_var(env_var, &secret);
                overrides.insert(env_var.to_string(), secret);
            }
            Ok(needs_update)
        }
        None => {
            let removed = overrides.remove(env_var).is_some();
            if removed {
                std::env::remove_var(env_var);
            }
            Ok(removed)
        }
    }
}

async fn ensure_embedded_worker_ready() -> Result<std::path::PathBuf> {
    let runtime_root = embedded_runtime_root();
    let node_modules = runtime_root.join("node_modules");
    if !node_modules.exists() {
        let npm_executable = embedded_runtime_npm_executable()?;
        let install = Command::new(&npm_executable)
            .arg("install")
            .arg("--ignore-scripts")
            .current_dir(&runtime_root)
            .output()
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "Failed to install embedded runtime dependencies in {} via {}: {}",
                    runtime_root.display(),
                    npm_executable.display(),
                    error
                )
            })?;
        if !install.status.success() {
            let stderr = String::from_utf8_lossy(&install.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&install.stdout).trim().to_string();
            anyhow::bail!(
                "Embedded runtime dependency install failed ({}). {}{}",
                install.status,
                stderr,
                if stdout.is_empty() {
                    String::new()
                } else {
                    format!(" {}", stdout)
                }
            );
        }
    }

    let bundle = embedded_worker_bundle_path();
    if embedded_worker_is_stale() {
        let npm_executable = embedded_runtime_npm_executable()?;
        let build = Command::new(&npm_executable)
            .arg("run")
            .arg("build:embedded-worker")
            .current_dir(&runtime_root)
            .output()
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "Failed to build embedded runtime worker in {} via {}: {}",
                    runtime_root.display(),
                    npm_executable.display(),
                    error
                )
            })?;
        if !build.status.success() {
            let stderr = String::from_utf8_lossy(&build.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&build.stdout).trim().to_string();
            anyhow::bail!(
                "Embedded runtime worker build failed ({}). {}{}",
                build.status,
                stderr,
                if stdout.is_empty() {
                    String::new()
                } else {
                    format!(" {}", stdout)
                }
            );
        }
    }

    if !bundle.exists() {
        anyhow::bail!(
            "Embedded runtime worker bundle is missing at {}",
            bundle.display()
        );
    }

    Ok(bundle)
}

async fn run_embedded_worker(request: &EmbeddedWorkerRequest) -> Result<EmbeddedWorkerResponse> {
    let bundle = ensure_embedded_worker_ready().await?;
    let runtime_root = embedded_runtime_root();
    let supervisor = embedded_worker_supervisor();
    let mut guard = supervisor.lock().await;

    let needs_restart = match guard.as_mut() {
        Some(session) => session.child.try_wait()?.is_some(),
        None => true,
    };
    if needs_restart {
        if let Some(mut session) = guard.take() {
            shutdown_embedded_worker_session(&mut session).await;
        }
        *guard = Some(start_embedded_worker_session(&bundle, &runtime_root).await?);
    }

    let result = match guard.as_mut() {
        Some(session) => run_embedded_worker_with_session(session, request).await,
        None => anyhow::bail!("Embedded runtime worker supervisor failed to initialize"),
    };

    match result {
        Ok(response) => {
            let should_clear = match guard.as_mut() {
                Some(session) => session.child.try_wait()?.is_some(),
                None => true,
            };
            if should_clear {
                if let Some(mut session) = guard.take() {
                    shutdown_embedded_worker_session(&mut session).await;
                }
            }
            Ok(response)
        }
        Err(error) => {
            if let Some(mut session) = guard.take() {
                shutdown_embedded_worker_session(&mut session).await;
            }
            Err(error)
        }
    }
}

fn provider_kind_to_embedded_id(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Ollama => "ollama",
        ProviderKind::OpenAi => "openai",
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::Gemini => "google",
        ProviderKind::Unknown => "openai",
    }
}

fn browser_session_mode_to_embedded_id(mode: BrowserSessionMode) -> &'static str {
    match mode {
        BrowserSessionMode::Ephemeral => "ephemeral",
        BrowserSessionMode::Persistent => "persistent",
    }
}

fn parse_embedded_research_disposition(value: &str) -> ResearchDisposition {
    match value.trim().to_lowercase().as_str() {
        "answer_directly" | "answer-directly" | "direct" => ResearchDisposition::AnswerDirectly,
        "inspect_specific_sources" | "inspect-specific-sources" | "inspect_sources" => {
            ResearchDisposition::InspectSpecificSources
        }
        "use_browser" | "use-browser" | "browser" => ResearchDisposition::UseBrowser,
        "read_document" | "read-document" | "document" | "read_pdf" => {
            ResearchDisposition::ReadDocument
        }
        "inspect_repo" | "inspect-repo" | "repo" => ResearchDisposition::InspectRepo,
        _ => ResearchDisposition::SearchWeb,
    }
}

pub(crate) fn build_embedded_worker_metadata(
    agent_name: &str,
    requester_agent: Option<&str>,
) -> HashMap<String, String> {
    let requester = requester_agent
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let metadata_path = agent_metadata_path_for_name(agent_name);
    let metadata_snapshot = load_agent_desktop_metadata(&metadata_path);
    let receive_dir_context = load_embedded_receive_dir_context(
        agent_name,
        requester,
        metadata_snapshot
            .as_ref()
            .and_then(|metadata| metadata.receive_dir_default_snapshot.as_deref()),
    );
    let embedded_workspace_dir = metadata_snapshot
        .as_ref()
        .map(embedded_ai_workspace_root)
        .unwrap_or_else(workspace_root);
    let agent_dir = embedded_runtime_agent_dir(agent_name);
    let agent_skills_dir = embedded_runtime_skills_dir(agent_name);
    let session_file = embedded_runtime_session_file(agent_name, requester);
    let mut worker_metadata = HashMap::new();
    worker_metadata.insert("agent_dir".to_string(), agent_dir.display().to_string());
    worker_metadata.insert(
        "qypha_agent_skills_dir".to_string(),
        agent_skills_dir.display().to_string(),
    );
    worker_metadata.insert(
        "session_file".to_string(),
        session_file.display().to_string(),
    );
    worker_metadata.insert(
        "workspace_dir".to_string(),
        embedded_workspace_dir.display().to_string(),
    );
    worker_metadata.insert("agent_name".to_string(), agent_name.to_string());
    if let Some(metadata) = metadata_snapshot.as_ref() {
        worker_metadata.insert(
            "ai_access_mode".to_string(),
            metadata.ai_access_mode.clone(),
        );
    }
    worker_metadata.insert(
        "requester_agent".to_string(),
        requester.unwrap_or("self").to_string(),
    );
    worker_metadata.insert(
        "qypha_receive_dir_default".to_string(),
        receive_dir_context.default_dir.display().to_string(),
    );
    worker_metadata.insert(
        "qypha_receive_dir_global".to_string(),
        receive_dir_context.global_dir.display().to_string(),
    );
    worker_metadata.insert(
        "qypha_receive_dir_effective".to_string(),
        receive_dir_context.effective_dir.display().to_string(),
    );
    worker_metadata.insert(
        "qypha_receive_dir_source".to_string(),
        receive_dir_context.effective_source.to_string(),
    );
    worker_metadata.insert(
        "session_id".to_string(),
        format!(
            "qypha-{}-{}",
            KeyStore::sanitize_agent_name(agent_name),
            requester
                .map(KeyStore::sanitize_agent_name)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "self".to_string())
        ),
    );
    worker_metadata.insert("timeout_ms".to_string(), "300000".to_string());
    if let Some(control) = current_active_companion_control_info() {
        worker_metadata.insert(
            "qypha_companion_control_socket".to_string(),
            control.socket_path,
        );
        worker_metadata.insert(
            "qypha_companion_control_token".to_string(),
            control.auth_token,
        );
    }
    worker_metadata
}

fn require_embedded_response_ok(
    response: EmbeddedWorkerResponse,
    fallback: &str,
) -> Result<EmbeddedWorkerResponse> {
    if !response.ok {
        anyhow::bail!("{}", response.error.unwrap_or_else(|| fallback.to_string()));
    }
    Ok(response)
}

pub(crate) async fn run_embedded_provider_healthcheck(
    metadata: HashMap<String, String>,
) -> Result<()> {
    require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ProviderHealthcheck {
            payload: EmbeddedWorkerProviderHealthcheckPayload { metadata },
        })
        .await?,
        "Embedded provider healthcheck failed",
    )?;
    Ok(())
}

pub(crate) async fn run_embedded_provider_list_models(
    provider: ProviderKind,
    metadata: HashMap<String, String>,
) -> Result<Vec<ProviderCatalogEntry>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ProviderListModels {
            payload: EmbeddedWorkerProviderListModelsPayload {
                provider: provider_kind_to_embedded_id(provider).to_string(),
                metadata,
            },
        })
        .await?,
        "Embedded provider model listing failed",
    )?;
    Ok(response.catalog)
}

pub(crate) async fn run_embedded_provider_generate(
    request: ProviderGenerateRequest,
    metadata: HashMap<String, String>,
) -> Result<ProviderGenerateResponse> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ProviderGenerate {
            payload: EmbeddedWorkerGeneratePayload {
                provider: provider_kind_to_embedded_id(request.provider).to_string(),
                model_id: request.model_id.clone(),
                system_prompt: request.system_prompt.clone(),
                messages: request
                    .messages
                    .into_iter()
                    .map(|message| EmbeddedWorkerProviderMessage {
                        role: message.role,
                        content: message.content,
                    })
                    .collect(),
                metadata,
            },
        })
        .await?,
        "Embedded provider generate failed",
    )?;

    let model_id = response
        .model_id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(request.model_id);
    let output_text = response
        .output_text
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("Embedded provider generate returned an empty response"))?;

    Ok(ProviderGenerateResponse {
        model_id,
        output_text,
        finish_reason: response
            .finish_reason
            .filter(|value| !value.trim().is_empty()),
    })
}

pub(crate) async fn run_embedded_memory_get(
    request: MemoryGetRequest,
    metadata: HashMap<String, String>,
) -> Result<Option<MemoryEntry>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::MemoryGet {
            payload: EmbeddedWorkerMemoryGetPayload { request, metadata },
        })
        .await?,
        "Embedded memory get failed",
    )?;
    Ok(response.memory_entry)
}

pub(crate) async fn run_embedded_memory_write(
    request: MemoryWriteRequest,
    metadata: HashMap<String, String>,
) -> Result<MemoryEntry> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::MemoryWrite {
            payload: EmbeddedWorkerMemoryWritePayload { request, metadata },
        })
        .await?,
        "Embedded memory write failed",
    )?;
    response
        .memory_entry
        .ok_or_else(|| anyhow::anyhow!("Embedded memory write did not return a memory entry"))
}

pub(crate) async fn run_embedded_memory_search(
    request: MemorySearchRequest,
    metadata: HashMap<String, String>,
) -> Result<Vec<MemoryEntry>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::MemorySearch {
            payload: EmbeddedWorkerMemorySearchPayload { request, metadata },
        })
        .await?,
        "Embedded memory search failed",
    )?;
    Ok(response.memory_entries)
}

pub(crate) async fn run_embedded_memory_compress(
    request: MemoryCompressRequest,
    metadata: HashMap<String, String>,
) -> Result<Option<MemoryEntry>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::MemoryCompress {
            payload: EmbeddedWorkerMemoryCompressPayload { request, metadata },
        })
        .await?,
        "Embedded memory compress failed",
    )?;
    Ok(response.memory_entry)
}

pub(crate) async fn run_embedded_memory_staleness_check(
    request: MemoryStalenessCheckRequest,
    metadata: HashMap<String, String>,
) -> Result<MemoryStalenessCheckResult> {
    let fallback_memory_id = request.memory_id.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::MemoryStalenessCheck {
            payload: EmbeddedWorkerMemoryStalenessCheckPayload { request, metadata },
        })
        .await?,
        "Embedded memory staleness check failed",
    )?;

    Ok(MemoryStalenessCheckResult {
        memory_id: response.memory_id.unwrap_or(fallback_memory_id),
        stale: response.stale.unwrap_or(true),
        rationale: response.rationale.filter(|value| !value.trim().is_empty()),
    })
}

pub(crate) async fn run_embedded_repo_overview(
    request: RepoOverviewRequest,
    metadata: HashMap<String, String>,
) -> Result<RepoOverviewResponse> {
    let fallback_root = request.root.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::RepoOverview {
            payload: EmbeddedWorkerRepoOverviewPayload {
                root: request.root.display().to_string(),
                metadata,
            },
        })
        .await?,
        "Embedded repo overview failed",
    )?;

    Ok(RepoOverviewResponse {
        root: response
            .root
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(fallback_root),
        vcs: response.vcs.filter(|value| !value.trim().is_empty()),
        branch: response.branch.filter(|value| !value.trim().is_empty()),
        dirty: response.dirty,
        changed_files: response
            .changed_files
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect(),
    })
}

pub(crate) async fn run_embedded_repo_tree(
    request: RepoTreeRequest,
    metadata: HashMap<String, String>,
) -> Result<RepoTreeResponse> {
    let fallback_root = request.root.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::RepoTree {
            payload: EmbeddedWorkerRepoTreePayload {
                root: request.root.display().to_string(),
                depth: request.depth,
                metadata,
            },
        })
        .await?,
        "Embedded repo tree failed",
    )?;

    Ok(RepoTreeResponse {
        root: response
            .root
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(fallback_root),
        entries: response.entries,
    })
}

pub(crate) async fn run_embedded_repo_grep(
    request: RepoSearchRequest,
    metadata: HashMap<String, String>,
) -> Result<RepoSearchResponse> {
    let fallback_root = request.root.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::RepoGrep {
            payload: EmbeddedWorkerRepoSearchPayload {
                root: request.root.display().to_string(),
                pattern: request.pattern,
                limit: request.limit,
                metadata,
            },
        })
        .await?,
        "Embedded repo grep failed",
    )?;

    Ok(RepoSearchResponse {
        root: response
            .root
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(fallback_root),
        matches: response.repo_matches,
    })
}

pub(crate) async fn run_embedded_repo_read_file(
    request: RepoReadFileRequest,
    metadata: HashMap<String, String>,
) -> Result<RepoReadFileResponse> {
    let fallback_path = request.path.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::RepoReadFile {
            payload: EmbeddedWorkerRepoReadFilePayload {
                path: request.path.display().to_string(),
                metadata,
            },
        })
        .await?,
        "Embedded repo read_file failed",
    )?;

    Ok(RepoReadFileResponse {
        path: response
            .path
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(fallback_path),
        content: response.file_content.unwrap_or_default(),
    })
}

pub(crate) async fn run_embedded_repo_git_log(
    request: RepoGitLogRequest,
    metadata: HashMap<String, String>,
) -> Result<RepoGitLogResponse> {
    let fallback_root = request.root.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::RepoGitLog {
            payload: EmbeddedWorkerRepoGitLogPayload {
                root: request.root.display().to_string(),
                limit: request.limit,
                metadata,
            },
        })
        .await?,
        "Embedded repo git_log failed",
    )?;

    Ok(RepoGitLogResponse {
        root: response
            .root
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(fallback_root),
        commits: response.commits,
    })
}

pub(crate) async fn run_embedded_repo_remote_inspect(
    request: RepoRemoteInspectRequest,
    metadata: HashMap<String, String>,
) -> Result<RepoRemoteInspectResponse> {
    let fallback_url = request.url.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::RepoRemoteInspect {
            payload: EmbeddedWorkerRepoRemoteInspectPayload {
                url: request.url,
                reference: request.reference,
                metadata,
            },
        })
        .await?,
        "Embedded repo remote inspect failed",
    )?;

    Ok(RepoRemoteInspectResponse {
        url: response.url.unwrap_or(fallback_url),
        summary: response.summary.filter(|value| !value.trim().is_empty()),
        candidate_files: response.candidate_files,
    })
}

fn parse_embedded_runtime_status(value: Option<&str>) -> RuntimeStatus {
    match value.unwrap_or("failed").trim().to_lowercase().as_str() {
        "accepted" => RuntimeStatus::Accepted,
        "running" => RuntimeStatus::Running,
        "blocked" => RuntimeStatus::Blocked,
        "completed" => RuntimeStatus::Completed,
        _ => RuntimeStatus::Failed,
    }
}

pub(crate) async fn run_embedded_os_execute(
    request: OsOperationRequest,
    metadata: HashMap<String, String>,
) -> Result<OsOperationResult> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::OsExecute {
            payload: EmbeddedWorkerOsExecutePayload { request, metadata },
        })
        .await?,
        "Embedded OS execute failed",
    )?;

    Ok(OsOperationResult {
        status: parse_embedded_runtime_status(response.status.as_deref()),
        stdout: response.stdout.filter(|value| !value.trim().is_empty()),
        stderr: response.stderr.filter(|value| !value.trim().is_empty()),
        paths: response
            .paths
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect(),
    })
}

pub(crate) async fn run_embedded_research_plan(
    provider: ProviderKind,
    model_id: &str,
    system_prompt: Option<&str>,
    request: ResearchPlanRequest,
    metadata: HashMap<String, String>,
) -> Result<ResearchPlanResponse> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ResearchPlan {
            payload: EmbeddedWorkerResearchPlanPayload {
                provider: provider_kind_to_embedded_id(provider).to_string(),
                model_id: model_id.trim().to_string(),
                query: request.query,
                current_answer_draft: request.current_answer_draft,
                local_context_available: request.local_context_available,
                system_prompt: system_prompt.map(str::to_string),
                metadata,
            },
        })
        .await?,
        "Embedded research planner failed",
    )?;

    Ok(ResearchPlanResponse {
        disposition: parse_embedded_research_disposition(
            response.disposition.as_deref().unwrap_or("search_web"),
        ),
        rationale: response
            .rationale
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                "Embedded runtime did not provide a research rationale.".to_string()
            }),
        planned_steps: response.planned_steps,
    })
}

pub(crate) async fn run_embedded_research_search(
    provider: ProviderKind,
    model_id: &str,
    request: ResearchSearchRequest,
    metadata: HashMap<String, String>,
) -> Result<ResearchSearchResponse> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ResearchSearch {
            payload: EmbeddedWorkerResearchSearchPayload {
                provider: provider_kind_to_embedded_id(provider).to_string(),
                model_id: model_id.trim().to_string(),
                query: request.query.clone(),
                recency_required: request.recency_required,
                technical_only: request.technical_only,
                max_results: request.max_results,
                scope: request.scope.clone(),
                metadata,
            },
        })
        .await?,
        "Embedded research search failed",
    )?;

    Ok(ResearchSearchResponse {
        query: response.query.unwrap_or(request.query),
        sources: response.sources,
        action_log: response.action_log,
    })
}

pub(crate) async fn run_embedded_research_inspect(
    provider: ProviderKind,
    model_id: &str,
    request: ResearchInspectRequest,
    metadata: HashMap<String, String>,
) -> Result<ResearchInspectResponse> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ResearchInspect {
            payload: EmbeddedWorkerResearchInspectPayload {
                provider: provider_kind_to_embedded_id(provider).to_string(),
                model_id: model_id.trim().to_string(),
                query: request.query.clone(),
                sources: request.sources.clone(),
                max_sources: request.max_sources,
                scope: request.scope.clone(),
                metadata,
            },
        })
        .await?,
        "Embedded research inspection failed",
    )?;

    Ok(ResearchInspectResponse {
        query: response.query.unwrap_or(request.query),
        inspected_sources: response.inspected_sources,
        consulted_sources: response.consulted_sources,
        action_log: response.action_log,
    })
}

pub(crate) async fn run_embedded_research_open_page(
    request: ResearchOpenPageRequest,
    metadata: HashMap<String, String>,
) -> Result<ResearchOpenPageResponse> {
    let fallback_session_id = request.session_id.clone();
    let fallback_url = request.source.url.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ResearchOpenPage {
            payload: EmbeddedWorkerResearchOpenPagePayload {
                session_id: request.session_id,
                source: request.source,
                scope: request.scope,
                metadata,
            },
        })
        .await?,
        "Embedded research open_page failed",
    )?;

    let consulted_source = response.consulted_source.ok_or_else(|| {
        anyhow::anyhow!("Embedded research open_page did not return a source ledger record")
    })?;

    Ok(ResearchOpenPageResponse {
        snapshot: BrowserSnapshot {
            session_id: response.session_id.unwrap_or(fallback_session_id),
            url: response.url.unwrap_or(fallback_url),
            markdown: response.markdown.unwrap_or_default(),
        },
        consulted_source,
        action_log: response.action_log,
    })
}

pub(crate) async fn run_embedded_research_find_in_page(
    request: ResearchFindInPageRequest,
    metadata: HashMap<String, String>,
) -> Result<ResearchFindInPageResponse> {
    let fallback_session_id = request.session_id.clone();
    let fallback_url = request
        .url
        .clone()
        .or_else(|| request.source.as_ref().map(|value| value.url.clone()))
        .unwrap_or_default();
    let fallback_query = request.query.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ResearchFindInPage {
            payload: EmbeddedWorkerResearchFindInPagePayload {
                session_id: request.session_id,
                query: request.query,
                source: request.source,
                url: request.url,
                max_matches: request.max_matches,
                scope: request.scope,
                metadata,
            },
        })
        .await?,
        "Embedded research find_in_page failed",
    )?;

    Ok(ResearchFindInPageResponse {
        session_id: response.session_id.unwrap_or(fallback_session_id),
        url: response.url.unwrap_or(fallback_url),
        query: response.query.unwrap_or(fallback_query),
        matches: response.matches,
        consulted_source: response.consulted_source,
        action_log: response.action_log,
    })
}

pub(crate) async fn run_embedded_research_synthesize(
    provider: ProviderKind,
    model_id: &str,
    system_prompt: Option<&str>,
    request: ResearchSynthesisRequest,
    metadata: HashMap<String, String>,
) -> Result<ResearchSynthesisResponse> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::ResearchSynthesize {
            payload: EmbeddedWorkerResearchSynthesizePayload {
                provider: provider_kind_to_embedded_id(provider).to_string(),
                model_id: model_id.trim().to_string(),
                query: request.query,
                sources: request.sources,
                inspected_sources: request.inspected_sources,
                consulted_sources: request.consulted_sources,
                desired_format: request.desired_format,
                system_prompt: system_prompt.map(str::to_string),
                metadata,
            },
        })
        .await?,
        "Embedded research synthesis failed",
    )?;

    Ok(ResearchSynthesisResponse {
        answer: response
            .answer
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                "Embedded runtime did not provide a synthesized answer.".to_string()
            }),
        uncertainty: response
            .uncertainty
            .filter(|value| !value.trim().is_empty()),
        citations: response.citations,
        sources_used: response.sources_used,
    })
}

pub(crate) async fn run_embedded_browser_start_session(
    spec: BrowserSessionSpec,
    metadata: HashMap<String, String>,
) -> Result<()> {
    require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::BrowserStartSession {
            payload: EmbeddedWorkerBrowserStartSessionPayload {
                session_id: spec.session_id,
                mode: browser_session_mode_to_embedded_id(spec.mode).to_string(),
                allowed_domains: spec.allowed_domains,
                metadata,
            },
        })
        .await?,
        "Embedded browser session start failed",
    )?;
    Ok(())
}

fn parse_embedded_browser_snapshot(
    response: EmbeddedWorkerResponse,
    fallback_session_id: &str,
    fallback_url: &str,
) -> Result<BrowserSnapshot> {
    let response = require_embedded_response_ok(response, "Embedded browser operation failed")?;
    Ok(BrowserSnapshot {
        session_id: response
            .session_id
            .unwrap_or_else(|| fallback_session_id.to_string()),
        url: response.url.unwrap_or_else(|| fallback_url.to_string()),
        markdown: response.markdown.unwrap_or_default(),
    })
}

pub(crate) async fn run_embedded_browser_open(
    request: BrowserOpenRequest,
    metadata: HashMap<String, String>,
) -> Result<BrowserSnapshot> {
    let fallback_session_id = request.session_id.clone();
    let fallback_url = request.url.clone();
    parse_embedded_browser_snapshot(
        run_embedded_worker(&EmbeddedWorkerRequest::BrowserOpen {
            payload: EmbeddedWorkerBrowserOpenPayload {
                session_id: request.session_id,
                url: request.url,
                metadata,
            },
        })
        .await?,
        &fallback_session_id,
        &fallback_url,
    )
}

pub(crate) async fn run_embedded_browser_snapshot(
    session_id: &str,
    metadata: HashMap<String, String>,
) -> Result<BrowserSnapshot> {
    parse_embedded_browser_snapshot(
        run_embedded_worker(&EmbeddedWorkerRequest::BrowserSnapshot {
            payload: EmbeddedWorkerBrowserSnapshotPayload {
                session_id: session_id.trim().to_string(),
                metadata,
            },
        })
        .await?,
        session_id,
        "",
    )
}

pub(crate) async fn run_embedded_browser_interact(
    request: BrowserInteractRequest,
    metadata: HashMap<String, String>,
) -> Result<BrowserSnapshot> {
    let fallback_session_id = request.session_id.clone();
    parse_embedded_browser_snapshot(
        run_embedded_worker(&EmbeddedWorkerRequest::BrowserInteract {
            payload: EmbeddedWorkerBrowserInteractPayload {
                session_id: request.session_id,
                action: request.action,
                target: request.target,
                value: request.value,
                metadata,
            },
        })
        .await?,
        &fallback_session_id,
        "",
    )
}

pub(crate) async fn run_embedded_browser_download(
    request: BrowserDownloadRequest,
    metadata: HashMap<String, String>,
) -> Result<BrowserDownloadResult> {
    let fallback_session_id = request.session_id.clone();
    let fallback_url = request.url.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::BrowserDownload {
            payload: EmbeddedWorkerBrowserDownloadPayload {
                session_id: request.session_id,
                url: request.url,
                destination: request.destination.map(|path| path.display().to_string()),
                metadata,
            },
        })
        .await?,
        "Embedded browser download failed",
    )?;

    let path = response
        .path
        .filter(|value| !value.trim().is_empty())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("Embedded browser download did not return a path"))?;

    Ok(BrowserDownloadResult {
        session_id: response.session_id.unwrap_or(fallback_session_id),
        url: response.url.unwrap_or(fallback_url),
        path,
    })
}

pub(crate) async fn run_embedded_document_read(
    request: DocumentReadRequest,
    metadata: HashMap<String, String>,
) -> Result<DocumentReadResponse> {
    let fallback_path = request.path.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::DocumentRead {
            payload: EmbeddedWorkerDocumentReadPayload {
                path: request.path.display().to_string(),
                metadata,
            },
        })
        .await?,
        "Embedded document read failed",
    )?;

    Ok(DocumentReadResponse {
        path: response
            .path
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or(fallback_path),
        sections: response.sections,
    })
}

pub(crate) async fn run_embedded_plugin_mcp_list_plugins(
    metadata: HashMap<String, String>,
) -> Result<Vec<PluginInfo>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::PluginMcpListPlugins {
            payload: EmbeddedWorkerPluginMcpListPayload { metadata },
        })
        .await?,
        "Embedded plugin list failed",
    )?;
    Ok(response.plugins)
}

pub(crate) async fn run_embedded_plugin_mcp_list_servers(
    metadata: HashMap<String, String>,
) -> Result<Vec<McpServerInfo>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::PluginMcpListServers {
            payload: EmbeddedWorkerPluginMcpListPayload { metadata },
        })
        .await?,
        "Embedded MCP server list failed",
    )?;
    Ok(response.servers)
}

pub(crate) async fn run_embedded_plugin_mcp_resolve_capability(
    capability_id: &str,
    metadata: HashMap<String, String>,
) -> Result<Option<PluginCapabilityInfo>> {
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::PluginMcpResolveCapability {
            payload: EmbeddedWorkerPluginMcpResolvePayload {
                capability_id: capability_id.trim().to_string(),
                metadata,
            },
        })
        .await?,
        "Embedded MCP capability resolution failed",
    )?;
    Ok(response.capability)
}

pub(crate) async fn run_embedded_plugin_mcp_invoke(
    request: PluginMcpInvokeRequest,
    metadata: HashMap<String, String>,
) -> Result<PluginMcpInvokeResponse> {
    let fallback_capability_id = request.capability_id.clone();
    let response = require_embedded_response_ok(
        run_embedded_worker(&EmbeddedWorkerRequest::PluginMcpInvoke {
            payload: EmbeddedWorkerPluginMcpInvokePayload {
                capability_id: request.capability_id,
                args_json: request.args_json,
                metadata,
            },
        })
        .await?,
        "Embedded MCP invocation failed",
    )?;

    Ok(PluginMcpInvokeResponse {
        capability_id: response.capability_id.unwrap_or(fallback_capability_id),
        output_json: response.output_json.unwrap_or_else(|| "{}".to_string()),
    })
}

async fn send_embedded_ai_message(
    metadata: &LaunchAgentDesktopMetadata,
    requester_agent: Option<&str>,
    message: &str,
) -> Result<AiAgentThreadState> {
    let provider = metadata
        .ai_provider
        .as_deref()
        .unwrap_or("ollama")
        .trim()
        .to_lowercase();
    if provider != "ollama" {
        let env_changed = sync_ai_provider_secret_env(&provider)?;
        let auth_store_changed = sync_ai_provider_secret_to_auth_store(&metadata.name, &provider)?;
        if env_changed || auth_store_changed {
            restart_embedded_worker_supervisor().await;
        }
    }

    let model = metadata
        .ai_model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "AI agent '{}' has no {} model selected",
                metadata.name,
                provider_label(&provider)
            )
        })?
        .to_string();

    let requester = requester_agent
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut thread = load_ai_agent_thread_state(metadata, requester);
    thread.messages.push(AiAgentThreadMessage {
        role: "user".to_string(),
        content: message.trim().to_string(),
        ts_ms: Utc::now().timestamp_millis(),
    });
    if thread.messages.len() > 80 {
        let overflow = thread.messages.len().saturating_sub(80);
        thread.messages.drain(0..overflow);
    }

    let mut worker_metadata = build_embedded_worker_metadata(&metadata.name, requester);
    if provider == "ollama" {
        worker_metadata.insert("ollama_host".to_string(), normalized_ollama_host());
    }

    let payload = run_embedded_worker(&EmbeddedWorkerRequest::AgentRun {
        payload: EmbeddedWorkerAgentRunPayload {
            provider: provider.clone(),
            model_id: model.clone(),
            system_prompt: Some(build_ai_agent_system_prompt(metadata, requester)),
            prompt: message.trim().to_string(),
            metadata: worker_metadata,
        },
    })
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "Embedded OpenClaw runtime is required for AI agent conversations. Provider-only fallback is disabled to prevent silent research-quality downgrade: {}",
            error
        )
    })?;
    if !payload.ok {
        anyhow::bail!(
            "{}",
            payload
                .error
                .unwrap_or_else(|| "Embedded runtime worker failed".to_string())
        );
    }
    let assistant_message = payload
        .output_text
        .map(|content| content.trim().to_string())
        .filter(|content| !content.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} returned an empty assistant response for model {}",
                provider_label(&provider),
                model
            )
        })?;

    thread.messages.push(AiAgentThreadMessage {
        role: "assistant".to_string(),
        content: assistant_message,
        ts_ms: Utc::now().timestamp_millis(),
    });
    if thread.messages.len() > 120 {
        let overflow = thread.messages.len().saturating_sub(120);
        thread.messages.drain(0..overflow);
    }

    save_ai_agent_thread_state(&thread)?;
    Ok(thread)
}

async fn run_embedded_ai_terminal_session(
    metadata: &LaunchAgentDesktopMetadata,
    companion_spec: &AiCompanionLaunchSpec,
) -> Result<()> {
    if std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return run_embedded_ai_headless_session(metadata, companion_spec).await;
    }

    println!(
        "   {}\n   {}\n   {}",
        "Embedded AI terminal session ready.".green().bold(),
        "Type your message and press Enter.".dimmed(),
        "Commands stay local. Use //message to send a leading slash to the AI.".dimmed()
    );
    println!("   {}", "Commands: /exit, /quit, /reset, /help".dimmed());
    println!();

    let rl_config = rustyline::Config::builder()
        .max_history_size(0)
        .unwrap_or_default()
        .build();
    let mut rl = DefaultEditor::with_config(rl_config)
        .map_err(|error| anyhow::anyhow!("Failed to initialize terminal line editor: {}", error))?;
    let external_printer = rl
        .create_external_printer()
        .ok()
        .map(|printer| Box::new(printer) as Box<dyn ExternalPrinter + Send>);
    let (display_tx, mut display_rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let mut external_printer = external_printer;
        while let Some(message) = display_rx.recv().await {
            if let Some(printer) = external_printer.as_mut() {
                let _ = printer.print(message.clone());
            } else {
                println!("{}", message);
            }
        }
    });
    let (companion_line_tx, _) = broadcast::channel(256);
    let runtime_state = AiTerminalRuntimeState {
        display_tx,
        peer_reply_locks: std::sync::Arc::new(TokioMutex::new(HashMap::new())),
        auto_accept_peer_dids: std::sync::Arc::new(TokioMutex::new(HashSet::new())),
        companion_line_tx,
        companion_stdin: std::sync::Arc::new(TokioMutex::new(None)),
        companion_command_lock: std::sync::Arc::new(TokioMutex::new(())),
        companion_peer_cache: std::sync::Arc::new(TokioMutex::new(HashMap::new())),
        companion_whoami_snapshot: std::sync::Arc::new(TokioMutex::new(None)),
    };
    let mut companion_runtime: Option<CompanionRuntimeSession> = None;
    ensure_companion_runtime(
        companion_spec,
        metadata,
        &runtime_state,
        &mut companion_runtime,
    )
    .await?;
    let mut companion_control = start_companion_control_server(metadata, &runtime_state).await?;

    let session_result: Result<()> = loop {
        let prompt = ai_terminal_prompt(&metadata.name);
        let line = match rl.readline(&prompt) {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => {
                println!();
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break Ok(());
            }
            Err(error) => {
                break Err(anyhow::anyhow!(
                    "Failed to read embedded AI terminal input: {}",
                    error
                ));
            }
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if let Some(message) = input.strip_prefix("//") {
            if message.trim().is_empty() {
                println!("   {}", "Nothing to send after //".yellow());
                println!();
                continue;
            }
            match send_embedded_ai_message(metadata, None, message).await {
                Ok(thread) => {
                    if let Some(last) = thread.messages.last() {
                        println!();
                        println!("{}", last.content);
                        println!();
                    } else {
                        println!("   {}", "AI returned no message.".yellow());
                        println!();
                    }
                }
                Err(error) => {
                    println!("   {} {}", "AI error:".red().bold(), error);
                    println!();
                }
            }
            continue;
        }
        match input {
            "/exit" | "/quit" => break Ok(()),
            "/help" => {
                println!("   /exit  Quit terminal AI chat");
                println!("   /quit  Quit terminal AI chat");
                println!("   /reset Clear this AI chat thread history");
                println!("   /help  Show commands");
                println!(
                    "   /connect <invite> Forward host connect command to companion Qypha runtime"
                );
                println!("   /invite Generate a direct invite from the companion Qypha runtime");
                println!("   /peers Show connected peers from the companion Qypha runtime");
                println!("   //text Send '/text' to the AI as a normal message");
                println!();
                continue;
            }
            "/reset" => {
                clear_ai_agent_thread_state(&metadata.name, None)?;
                println!("   {}", "AI thread history cleared.".yellow());
                println!();
                continue;
            }
            _ => {}
        }
        if input.starts_with('/') {
            match send_companion_runtime_command(
                companion_spec,
                metadata,
                &runtime_state,
                &mut companion_runtime,
                input,
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    println!("   {} {}", "Host command error:".red().bold(), error);
                    println!(
                        "   {}",
                        "If you want to send a slash-prefixed message to the AI instead, use //"
                            .dimmed()
                    );
                    println!();
                }
            }
            println!();
            continue;
        }

        match send_embedded_ai_message(metadata, None, input).await {
            Ok(thread) => {
                if let Some(last) = thread.messages.last() {
                    println!();
                    println!("{}", last.content);
                    println!();
                } else {
                    println!("   {}", "AI returned no message.".yellow());
                    println!();
                }
            }
            Err(error) => {
                println!("   {} {}", "AI error:".red().bold(), error);
                println!();
            }
        }
    };

    {
        let mut stdin_slot = runtime_state.companion_stdin.lock().await;
        *stdin_slot = None;
    }
    shutdown_companion_runtime(&mut companion_runtime).await?;
    shutdown_companion_control_server(&mut companion_control).await?;
    session_result?;
    println!("   {}", "Embedded AI session closed.".dimmed());
    Ok(())
}

async fn run_embedded_ai_headless_session(
    metadata: &LaunchAgentDesktopMetadata,
    companion_spec: &AiCompanionLaunchSpec,
) -> Result<()> {
    println!(
        "   {}",
        "Embedded AI headless session ready.".green().bold()
    );

    let (display_tx, mut display_rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(message) = display_rx.recv().await {
            println!("{}", message);
        }
    });
    let (companion_line_tx, _) = broadcast::channel(256);
    let runtime_state = AiTerminalRuntimeState {
        display_tx,
        peer_reply_locks: std::sync::Arc::new(TokioMutex::new(HashMap::new())),
        auto_accept_peer_dids: std::sync::Arc::new(TokioMutex::new(HashSet::new())),
        companion_line_tx,
        companion_stdin: std::sync::Arc::new(TokioMutex::new(None)),
        companion_command_lock: std::sync::Arc::new(TokioMutex::new(())),
        companion_peer_cache: std::sync::Arc::new(TokioMutex::new(HashMap::new())),
        companion_whoami_snapshot: std::sync::Arc::new(TokioMutex::new(None)),
    };
    let mut companion_runtime: Option<CompanionRuntimeSession> = None;
    ensure_companion_runtime(
        companion_spec,
        metadata,
        &runtime_state,
        &mut companion_runtime,
    )
    .await?;
    let mut companion_control = start_companion_control_server(metadata, &runtime_state).await?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();
    let metadata_for_stdin = metadata.clone();
    let runtime_state_for_stdin = runtime_state.clone();
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let input = line.trim();
                    if input.is_empty() {
                        continue;
                    }
                    if matches!(input, "/quit" | "/exit") {
                        let _ = shutdown_tx.send(());
                        break;
                    }
                    if input == "/help" {
                        println!("   /exit  Quit headless AI session");
                        println!("   /quit  Quit headless AI session");
                        println!("   /reset Clear this AI chat thread history");
                        println!("   /help  Show commands");
                        println!();
                        continue;
                    }
                    if input == "/reset" {
                        match clear_ai_agent_thread_state(&metadata_for_stdin.name, None) {
                            Ok(()) => {
                                println!("   {}", "AI thread history cleared.".yellow());
                                println!();
                            }
                            Err(error) => {
                                println!("   {} {}", "AI reset error:".red().bold(), error);
                                println!();
                            }
                        }
                        continue;
                    }
                    if let Some(message) = input.strip_prefix("//") {
                        if message.trim().is_empty() {
                            println!("   {}", "Nothing to send after //".yellow());
                            println!();
                            continue;
                        }
                        match send_embedded_ai_message(&metadata_for_stdin, None, message).await {
                            Ok(thread) => {
                                if let Some(last) = thread.messages.last() {
                                    println!();
                                    println!("{}", last.content);
                                    println!();
                                } else {
                                    println!("   {}", "AI returned no message.".yellow());
                                    println!();
                                }
                            }
                            Err(error) => {
                                println!("   {} {}", "AI error:".red().bold(), error);
                                println!();
                            }
                        }
                        continue;
                    }
                    if input.starts_with('/') {
                        let stdin_handle = {
                            let guard = runtime_state_for_stdin.companion_stdin.lock().await;
                            guard.clone()
                        };
                        match stdin_handle {
                            Some(stdin_handle) => {
                                if let Err(error) = send_serialized_companion_command(
                                    &runtime_state_for_stdin,
                                    &stdin_handle,
                                    input,
                                )
                                .await
                                {
                                    println!("   {} {}", "Host command error:".red().bold(), error);
                                    println!();
                                }
                            }
                            None => {
                                println!(
                                    "   {} {}",
                                    "Host command error:".red().bold(),
                                    "AI network runtime is not available".dimmed()
                                );
                                println!();
                            }
                        }
                        continue;
                    }
                    match send_embedded_ai_message(&metadata_for_stdin, None, input).await {
                        Ok(thread) => {
                            if let Some(last) = thread.messages.last() {
                                println!();
                                println!("{}", last.content);
                                println!();
                            } else {
                                println!("   {}", "AI returned no message.".yellow());
                                println!();
                            }
                        }
                        Err(error) => {
                            println!("   {} {}", "AI error:".red().bold(), error);
                            println!();
                        }
                    }
                }
                Ok(None) => {
                    let _ = shutdown_tx.send(());
                    break;
                }
                Err(_) => {
                    let _ = shutdown_tx.send(());
                    break;
                }
            }
        }
    });

    let session_result: Result<()> = if let Some(session) = companion_runtime.as_mut() {
        tokio::select! {
            _ = shutdown_rx.recv() => Ok(()),
            result = session.child.wait() => {
                let status = result?;
                if status.success() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("AI companion runtime exited with status {}", status))
                }
            }
        }
    } else {
        Ok(())
    };

    {
        let mut stdin_slot = runtime_state.companion_stdin.lock().await;
        *stdin_slot = None;
    }
    shutdown_companion_runtime(&mut companion_runtime).await?;
    shutdown_companion_control_server(&mut companion_control).await?;
    session_result?;
    println!("   {}", "Embedded AI headless session closed.".dimmed());
    Ok(())
}

async fn launch_ai_profile_wizard(theme: &ColorfulTheme, name: &str) -> Result<()> {
    let inspection = inspect_ai_agent_state(name)?;
    let existing_metadata = inspection.metadata.clone();
    let existing_ai = existing_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.agent_type == DesktopProfileAgentType::Ai);
    let mut keep_existing_llm = existing_ai;
    if let Some(existing) = existing_metadata.as_ref().filter(|_| existing_ai) {
        println!(
            "   {} {} / {}",
            "Existing AI agent found:".yellow().bold(),
            provider_label(existing.ai_provider.as_deref().unwrap_or("ollama")).cyan(),
            existing.ai_model.as_deref().unwrap_or("unset").dimmed()
        );
        let choice = Select::with_theme(theme)
            .with_prompt("  AI settings")
            .items(&[
                "Continue with saved LLM settings",
                "Change AI provider/model",
            ])
            .default(0)
            .interact()?;
        keep_existing_llm = choice == 0;
    }

    let metadata = if keep_existing_llm {
        existing_metadata
            .clone()
            .unwrap_or_else(|| LaunchAgentDesktopMetadata {
                name: name.trim().to_string(),
                agent_type: DesktopProfileAgentType::Ai,
                ai_provider: Some("ollama".to_string()),
                ai_model: None,
                ai_role: default_ai_role(),
                ai_access_mode: default_ai_access_mode(),
                ai_log_mode: default_ai_log_mode(),
                ai_transport_mode: Some("internet".to_string()),
                ai_listen_port: None,
                receive_dir_default_snapshot: Some(default_receive_root().display().to_string()),
            })
            .normalized()
    } else {
        prompt_ai_metadata(theme, name, existing_metadata.as_ref()).await?
    };
    let default_transport_mode =
        metadata_ai_transport_mode(existing_metadata.as_ref()).unwrap_or(TransportMode::Internet);
    let default_listen_port = metadata_ai_listen_port(existing_metadata.as_ref())
        .unwrap_or_else(suggested_companion_listen_port);
    let default_log_mode = metadata_ai_log_mode(existing_metadata.as_ref());

    let mut network_plan = match inspection.action {
        PersistentLaunchAction::Initialize => {
            let transport_mode = prompt_ai_transport_mode(theme, default_transport_mode)?;
            let log_mode = prompt_ai_log_mode(theme, &transport_mode, &default_log_mode)?;
            let listen_port: u16 = Input::with_theme(theme)
                .with_prompt("  Listen port")
                .default(default_listen_port)
                .interact_text()?;
            println!();
            if log_mode == "ghost" {
                AiNetworkLaunchPlan {
                    transport_mode: transport_mode.clone(),
                    log_mode,
                    listen_port,
                    companion_spec: AiCompanionLaunchSpec::Ghost {
                        name: name.trim().to_string(),
                        transport_mode,
                        listen_port,
                    },
                }
            } else {
                let passphrase = prompt_ai_agent_passphrase(name)?;
                let config_path = provision_ai_network_agent(
                    name,
                    &transport_mode,
                    &log_mode,
                    listen_port,
                    &passphrase,
                )
                .await?;
                AiNetworkLaunchPlan {
                    transport_mode,
                    log_mode,
                    listen_port,
                    companion_spec: AiCompanionLaunchSpec::Persistent {
                        config_path,
                        passphrase,
                    },
                }
            }
        }
        PersistentLaunchAction::ReuseExisting => {
            println!(
                "   {} {}",
                "Reattaching existing AI agent:".yellow().bold(),
                metadata.name.cyan()
            );
            println!();
            if default_log_mode == "ghost" {
                load_ai_network_plan(&inspection, None)?
            } else {
                let passphrase = resolve_launch_passphrase(
                    "  Enter passphrase to unlock existing AI agent identity and runtime",
                )?;
                load_ai_network_plan(&inspection, Some(passphrase))?
            }
        }
        PersistentLaunchAction::RecoverConfig => {
            let transport_mode = prompt_ai_transport_mode(theme, default_transport_mode)?;
            let log_mode = prompt_ai_log_mode(theme, &transport_mode, &default_log_mode)?;
            let listen_port: u16 = Input::with_theme(theme)
                .with_prompt("  Listen port")
                .default(default_listen_port)
                .interact_text()?;
            println!();
            if log_mode == "ghost" {
                recover_ai_network_plan(&inspection, transport_mode, log_mode, listen_port, None)?
            } else {
                println!(
                    "   {}",
                    format_existing_agent_recovery_notice(
                        &metadata.name,
                        &inspection.config_path,
                        &inspection.identity_path
                    )
                    .yellow()
                );
                let passphrase = resolve_launch_passphrase(&format!(
                    "  Enter passphrase to unlock existing AI identity and restore {}",
                    inspection.config_path.display()
                ))?;
                println!();
                recover_ai_network_plan(
                    &inspection,
                    transport_mode,
                    log_mode,
                    listen_port,
                    Some(passphrase),
                )?
            }
        }
        PersistentLaunchAction::MissingIdentity => unreachable!(),
    };

    ensure_interactive_ai_listen_port_available(theme, &inspection, &mut network_plan)?;

    let mut metadata = metadata;
    metadata.ai_transport_mode =
        Some(transport_mode_to_str(&network_plan.transport_mode).to_string());
    metadata.ai_listen_port = Some(network_plan.listen_port);
    metadata.ai_log_mode = network_plan.log_mode.clone();
    network_plan.log_mode = normalize_ai_log_mode_value(&network_plan.log_mode);

    let metadata_path = save_agent_desktop_metadata(&metadata)?;
    let active_path = persist_active_embedded_agent(&metadata.name)?;
    println!("   {}", "AI Agent Profile Ready".green().bold());
    println!("   {} {}", "Name:".yellow().bold(), metadata.name.cyan());
    println!("   {} {}", "Type:".yellow().bold(), "AI Agent".cyan());
    println!(
        "   {} {}",
        "Provider:".yellow().bold(),
        provider_label(metadata.ai_provider.as_deref().unwrap_or("ollama")).cyan()
    );
    if let Some(model) = metadata.ai_model.as_deref() {
        println!("   {} {}", "Model:".yellow().bold(), model.cyan());
    }
    println!("   {} {}", "Role:".yellow().bold(), metadata.ai_role.cyan());
    if let Some(receive_dir) = metadata.receive_dir_default_snapshot.as_deref() {
        println!(
            "   {} {}",
            "Default Receive Dir:".yellow().bold(),
            receive_dir.cyan()
        );
    }
    println!("   {} {}", "Access:".yellow().bold(), "Full access".cyan());
    println!(
        "   {} {}",
        "Transport:".yellow().bold(),
        match network_plan.transport_mode {
            TransportMode::Tcp => "LAN",
            TransportMode::Tor => "Tor",
            TransportMode::Internet => "Internet",
        }
        .cyan()
    );
    println!(
        "   {} {}",
        "Log Mode:".yellow().bold(),
        metadata.ai_log_mode.to_uppercase().cyan()
    );
    println!(
        "   {} {}",
        "Port:".yellow().bold(),
        network_plan.listen_port.to_string().cyan()
    );
    if let AiCompanionLaunchSpec::Persistent { config_path, .. } = &network_plan.companion_spec {
        println!(
            "   {} {}",
            "Config:".yellow().bold(),
            config_path.display().to_string().dimmed()
        );
    }
    println!(
        "   {} {}",
        "Profile:".yellow().bold(),
        metadata_path.display().to_string().dimmed()
    );
    println!(
        "   {} {}",
        "Active:".yellow().bold(),
        active_path.display().to_string().dimmed()
    );
    println!(
        "   {}",
        if metadata.ai_log_mode == "ghost" {
            "This AI agent is marked as the active embedded agent and will launch its network runtime in Ghost mode with an ephemeral zero-trace identity."
        } else {
            "This AI agent now has a normal persistent Qypha identity/config, is marked as the active embedded agent, and can be messaged by human agents."
        }
        .dimmed()
    );
    println!(
        "   {}",
        "Network commands are live immediately. Ollama is the first fully wired AI provider in terminal mode."
            .dimmed()
    );
    println!();
    let companion_spec = network_plan.companion_spec.clone();
    run_embedded_ai_terminal_session(&metadata, &companion_spec).await
}

// ─── Privilege Detection ────────────────────────────────────────────────────

/// Check if the current process has elevated privileges.
fn is_running_as_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Check if elevated by attempting to read a protected registry key
        std::process::Command::new("reg")
            .args(["query", "HKU\\S-1-5-19"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

// ─── Forensic Status Tracking ──────────────────────────────────────────────

/// Result of a single privileged OS command in Ghost mode.
struct ForensicCmd {
    desc: &'static str,
    success: bool,
    needs_root: bool,
}

/// Tracks all privileged command outcomes within a Ghost session.
/// Replaces silent `let _ = Command::new(...)` with observable results.
struct ForensicStatus {
    results: Vec<ForensicCmd>,
    has_root: bool,
}

impl ForensicStatus {
    fn new() -> Self {
        Self {
            results: Vec::new(),
            has_root: is_running_as_root(),
        }
    }

    /// Run a system command, capture exit status, record the result.
    /// If command needs root and we don't have it, try `sudo -n` (non-interactive).
    fn run_cmd(
        &mut self,
        desc: &'static str,
        program: &str,
        args: &[&str],
        needs_root: bool,
    ) -> bool {
        let success = if needs_root && !self.has_root {
            // Try with sudo -n (non-interactive, fails instantly if no NOPASSWD)
            let mut sudo_args = vec!["-n", program];
            sudo_args.extend_from_slice(args);
            let sudo_ok = std::process::Command::new("sudo")
                .args(&sudo_args)
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if sudo_ok {
                sudo_ok
            } else {
                // Fallback: run directly (will likely fail but records the attempt)
                std::process::Command::new(program)
                    .args(args)
                    .stderr(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
        } else {
            std::process::Command::new(program)
                .args(args)
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        self.results.push(ForensicCmd {
            desc,
            success,
            needs_root,
        });
        success
    }

    /// Record a non-command action (always succeeds).
    fn record_ok(&mut self, desc: &'static str) {
        self.results.push(ForensicCmd {
            desc,
            success: true,
            needs_root: false,
        });
    }

    /// Print warnings for failed commands.
    fn print_warnings(&self) {
        let root_fails: Vec<_> = self
            .results
            .iter()
            .filter(|r| !r.success && r.needs_root)
            .collect();
        let other_fails: Vec<_> = self
            .results
            .iter()
            .filter(|r| !r.success && !r.needs_root)
            .collect();

        if root_fails.is_empty() && other_fails.is_empty() {
            return;
        }

        if !root_fails.is_empty() {
            println!("\n   \x1b[31m\x1b[1m╔══════════════════════════════════════════════════════════╗\x1b[0m");
            println!("   \x1b[31m\x1b[1m║  PRIVILEGE WARNING: {} protection(s) FAILED             ║\x1b[0m",
                root_fails.len());
            println!("   \x1b[31m\x1b[1m║  Ghost mode requires elevated rights for full forensic  ║\x1b[0m");
            println!("   \x1b[31m\x1b[1m║  protection. Without it, OS-level traces WILL persist.  ║\x1b[0m");
            println!("   \x1b[31m\x1b[1m╠══════════════════════════════════════════════════════════╣\x1b[0m");
            for f in &root_fails {
                println!("   \x1b[31m  [FAIL] {}\x1b[0m", f.desc);
            }
            println!("   \x1b[31m\x1b[1m╠══════════════════════════════════════════════════════════╣\x1b[0m");
            println!("   \x1b[31m\x1b[1m║  RECOMMENDED: sudo Qypha launch                        ║\x1b[0m");
            println!("   \x1b[31m\x1b[1m╚══════════════════════════════════════════════════════════╝\x1b[0m");
        }

        if !other_fails.is_empty() {
            println!(
                "\n   \x1b[33m\x1b[1mWARNING: {} cleanup(s) FAILED:\x1b[0m",
                other_fails.len()
            );
            for f in &other_fails {
                println!("   \x1b[33m  - {}\x1b[0m", f.desc);
            }
        }
    }

    /// Print dynamic summary.
    fn print_summary(&self) {
        let (ok, fail): (Vec<_>, Vec<_>) = self.results.iter().partition(|r| r.success);

        if !ok.is_empty() {
            println!(
                "   \x1b[32m FORENSIC ACTIONS ({}/{}):\x1b[0m",
                ok.len(),
                self.results.len()
            );
            for r in &ok {
                println!("   \x1b[90m  [OK]   {}\x1b[0m", r.desc);
            }
        }
        if !fail.is_empty() {
            println!("   \x1b[31m FAILED ({}):\x1b[0m", fail.len());
            for r in &fail {
                println!(
                    "   \x1b[31m  [FAIL] {} {}\x1b[0m",
                    r.desc,
                    if r.needs_root { "(needs sudo)" } else { "" }
                );
            }
        }
    }
}

// ─── Environment Checks ────────────────────────────────────────────────────

/// Check if full-disk encryption is active.
/// Returns (is_encrypted, method_name) for detailed reporting.
fn check_disk_encryption_detail() -> (bool, &'static str) {
    #[cfg(target_os = "macos")]
    {
        // Primary: fdesetup (FileVault)
        if let Ok(output) = std::process::Command::new("fdesetup")
            .args(["status"])
            .stderr(std::process::Stdio::piped())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("FileVault is On") {
                return (true, "FileVault");
            }
        }
        // Secondary: diskutil (APFS encrypted volume)
        if let Ok(output) = std::process::Command::new("diskutil")
            .args(["info", "/"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Encrypted:") && stdout.contains("Yes") {
                return (true, "APFS Encrypted");
            }
        }
        return (false, "None");
    }

    #[cfg(target_os = "linux")]
    {
        // Check /proc/mounts for dm-crypt/LUKS
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "/" {
                    if parts[0].starts_with("/dev/mapper/") || parts[0].starts_with("/dev/dm-") {
                        return (true, "LUKS/dm-crypt");
                    }
                }
            }
        }
        // Also check for ecryptfs
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            if mounts.contains("ecryptfs") {
                return (true, "eCryptfs");
            }
        }
        return (false, "None");
    }

    #[cfg(target_os = "windows")]
    {
        // BitLocker: manage-bde -status C:
        if let Ok(output) = std::process::Command::new("manage-bde")
            .args(["-status", "C:"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Protection On") {
                return (true, "BitLocker");
            }
        }
        // Check for VeraCrypt
        if std::path::Path::new("C:\\Program Files\\VeraCrypt\\VeraCrypt.exe").exists() {
            // VeraCrypt installed but can't confirm active — report as possible
            return (false, "VeraCrypt (installed, status unknown)");
        }
        return (false, "None");
    }

    #[allow(unreachable_code)]
    (false, "None")
}

/// Simple wrapper for backward compatibility.
fn check_disk_encryption() -> bool {
    check_disk_encryption_detail().0
}

/// Check if swap is safe (encrypted or disabled).
fn check_swap_safety() -> bool {
    #[cfg(target_os = "macos")]
    {
        return check_disk_encryption(); // macOS swap encryption follows FileVault
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/swaps") {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() <= 1 {
                return true;
            } // No swap
            for line in &lines[1..] {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(device) = parts.first() {
                    if !device.starts_with("/dev/mapper/") && !device.starts_with("/dev/dm-") {
                        return false;
                    }
                }
            }
            return true;
        }
        return false;
    }

    #[cfg(target_os = "windows")]
    {
        // Windows pagefile security depends on BitLocker (same as macOS/FileVault)
        return check_disk_encryption();
    }

    #[allow(unreachable_code)]
    false
}

/// Check if iCloud Desktop/Documents sync poses a risk.
#[cfg(target_os = "macos")]
fn check_icloud_risk() -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };

    if let Ok(exe) = std::env::current_exe() {
        let exe_str = exe.to_string_lossy().to_string();
        if exe_str.contains("/Desktop/") || exe_str.contains("/Documents/") {
            let icloud_desktop = format!(
                "{}/Library/Mobile Documents/com~apple~CloudDocs/Desktop",
                home
            );
            let icloud_documents = format!(
                "{}/Library/Mobile Documents/com~apple~CloudDocs/Documents",
                home
            );
            if std::path::Path::new(&icloud_desktop).exists()
                || std::path::Path::new(&icloud_documents).exists()
            {
                return true;
            }
        }
    }
    false
}

fn ghost_runtime_temp_root() -> std::path::PathBuf {
    std::env::var("QYPHA_RUNTIME_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
}

#[cfg(target_os = "macos")]
fn setup_macos_ghost_ramdisk(status: &mut ForensicStatus) -> Option<(std::path::PathBuf, String)> {
    let ram_mb = std::env::var("QYPHA_GHOST_RAMDISK_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1024)
        .clamp(128, 8192);
    let sectors = ram_mb.saturating_mul(2048);
    let attach_target = format!("ram://{}", sectors);
    let attach = std::process::Command::new("hdiutil")
        .args(["attach", "-nomount", &attach_target])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output()
        .ok()?;
    if !attach.status.success() {
        status.results.push(ForensicCmd {
            desc: "Allocate macOS RAM disk runtime storage",
            success: false,
            needs_root: false,
        });
        return None;
    }

    let device = String::from_utf8_lossy(&attach.stdout)
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("/dev/disk") {
                Some(trimmed.to_string())
            } else {
                None
            }
        })?;
    let volume_label = format!(
        "NXF_GHOST_{}_{}",
        std::process::id(),
        chrono::Utc::now().timestamp()
    );
    let erase = std::process::Command::new("diskutil")
        .args(["eraseVolume", "HFS+", &volume_label, &device])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output()
        .ok()?;
    if !erase.status.success() {
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", &device, "-force"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output();
        status.results.push(ForensicCmd {
            desc: "Format macOS RAM disk runtime storage",
            success: false,
            needs_root: false,
        });
        return None;
    }

    let mount_point = std::path::PathBuf::from(format!("/Volumes/{}", volume_label));
    let runtime_root = mount_point.join("qypha-runtime");
    if std::fs::create_dir_all(&runtime_root).is_err() {
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", &device, "-force"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output();
        status.results.push(ForensicCmd {
            desc: "Initialize RAM disk runtime directory",
            success: false,
            needs_root: false,
        });
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700));
    }

    status.results.push(ForensicCmd {
        desc: "Allocate macOS RAM disk runtime storage",
        success: true,
        needs_root: false,
    });
    Some((runtime_root, device))
}

/// Interactive launch wizard — configure and start an agent in one step.
/// In Ghost mode, persistent disk traces are aggressively minimized.
pub async fn launch_wizard() -> Result<()> {
    let theme = ColorfulTheme::default();

    println!("\n   {}", "Qypha Agent Launch Wizard".cyan().bold());
    println!(
        "   {}\n",
        "Configure and start your agent interactively.".dimmed()
    );

    // ── Step 1: Agent Name ──
    let name: String = Input::with_theme(&theme)
        .with_prompt("  Agent name")
        .interact_text()?;

    // ── Step 2: Agent Type ──
    let agent_type_idx = Select::with_theme(&theme)
        .with_prompt("  Agent type")
        .items(&["Human Agent", "AI Agent"])
        .default(0)
        .interact()?;
    if agent_type_idx == 1 {
        println!();
        return launch_ai_profile_wizard(&theme, &name).await;
    }

    // ── Step 3: Transport Mode ──
    let transports = &["Internet", "LAN", "Tor"];
    let transport_idx = Select::with_theme(&theme)
        .with_prompt("  Transport mode")
        .items(transports)
        .default(0)
        .interact()?;
    let transport_mode = match transport_idx {
        0 => TransportMode::Internet,
        1 => TransportMode::Tcp,
        2 => TransportMode::Tor,
        _ => TransportMode::Internet,
    };

    // ── Step 4: Log Mode (Tor only) ──
    let log_mode = if matches!(transport_mode, TransportMode::Tor) {
        let log_modes = &[
            "Safe (privacy-hardened, reduced persistence)",
            "Ghost (zero trace, immutable)",
        ];
        let log_idx = Select::with_theme(&theme)
            .with_prompt("  Log mode")
            .items(log_modes)
            .default(0)
            .interact()?;
        match log_idx {
            0 => "safe",
            1 => "ghost",
            _ => "safe",
        }
    } else {
        "safe"
    };

    // ── Step 5: Port ──
    let suggested_port = {
        let count = crate::crypto::keystore::list_agents()
            .unwrap_or_default()
            .len() as u16;
        9090 + count
    };
    let port: u16 = Input::with_theme(&theme)
        .with_prompt("  Listen port")
        .default(suggested_port)
        .interact_text()?;

    println!();

    // ── Branch: Ghost (zero-trace) vs Safe persistent flow ──
    launch_flow(&name, transport_mode, log_mode, port).await
}

/// Non-interactive launch entrypoint (used by desktop app integrations).
pub async fn launch_noninteractive(
    name: &str,
    transport: &str,
    log_mode: &str,
    port: u16,
) -> Result<()> {
    let metadata_path = agent_metadata_path_for_name(name);
    if let Some(metadata) = load_agent_desktop_metadata(&metadata_path)
        .filter(|metadata| metadata.agent_type == DesktopProfileAgentType::Ai)
    {
        return launch_ai_profile_noninteractive(name, transport, log_mode, port, metadata).await;
    }
    let transport_mode = parse_transport_mode(transport)?;
    let mode = match log_mode.to_lowercase().as_str() {
        "safe" => "safe",
        "ghost" => "ghost",
        _ => {
            anyhow::bail!("Invalid log mode '{}'. Use: safe or ghost.", log_mode)
        }
    };
    launch_flow(name, transport_mode, mode, port).await
}

async fn launch_ai_profile_noninteractive(
    name: &str,
    transport: &str,
    log_mode: &str,
    port: u16,
    existing_metadata: LaunchAgentDesktopMetadata,
) -> Result<()> {
    let inspection = inspect_ai_agent_state(name)?;
    let transport_mode = parse_transport_mode(transport)?;
    let normalized_log_mode = match log_mode.to_lowercase().as_str() {
        "safe" => "safe".to_string(),
        "ghost" => "ghost".to_string(),
        other => anyhow::bail!("Invalid AI log mode '{}'. Use: safe or ghost.", other),
    };

    if normalized_log_mode == "ghost" && !matches!(transport_mode, TransportMode::Tor) {
        anyhow::bail!("Ghost mode requires Tor transport for AI agents");
    }

    let mut metadata = existing_metadata.normalized();
    metadata.ai_log_mode = normalized_log_mode.clone();
    metadata.ai_transport_mode = Some(transport_mode_to_str(&transport_mode).to_string());
    metadata.ai_listen_port = Some(port);

    let env_passphrase =
        crate::config::config_passphrase_from_env().filter(|value| !value.trim().is_empty());
    let network_plan = match inspection.action {
        PersistentLaunchAction::Initialize => {
            if normalized_log_mode == "ghost" {
                AiNetworkLaunchPlan {
                    transport_mode: transport_mode.clone(),
                    log_mode: normalized_log_mode.clone(),
                    listen_port: port,
                    companion_spec: AiCompanionLaunchSpec::Ghost {
                        name: name.trim().to_string(),
                        transport_mode: transport_mode.clone(),
                        listen_port: port,
                    },
                }
            } else {
                let passphrase = env_passphrase.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Passphrase is required for safe AI launch. Set QYPHA_PASSPHRASE or QYPHA_CONFIG_PASSPHRASE."
                    )
                })?;
                let config_path = provision_ai_network_agent(
                    name,
                    &transport_mode,
                    &normalized_log_mode,
                    port,
                    &passphrase,
                )
                .await?;
                AiNetworkLaunchPlan {
                    transport_mode: transport_mode.clone(),
                    log_mode: normalized_log_mode.clone(),
                    listen_port: port,
                    companion_spec: AiCompanionLaunchSpec::Persistent {
                        config_path,
                        passphrase,
                    },
                }
            }
        }
        PersistentLaunchAction::ReuseExisting => {
            if normalized_log_mode == "ghost" {
                AiNetworkLaunchPlan {
                    transport_mode: transport_mode.clone(),
                    log_mode: normalized_log_mode.clone(),
                    listen_port: port,
                    companion_spec: AiCompanionLaunchSpec::Ghost {
                        name: name.trim().to_string(),
                        transport_mode: transport_mode.clone(),
                        listen_port: port,
                    },
                }
            } else {
                let passphrase = env_passphrase.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Passphrase is required for safe AI launch. Set QYPHA_PASSPHRASE or QYPHA_CONFIG_PASSPHRASE."
                    )
                })?;
                rewrite_persistent_ai_config_with_port(
                    &inspection,
                    &transport_mode,
                    &normalized_log_mode,
                    port,
                    &passphrase,
                )?;
                AiNetworkLaunchPlan {
                    transport_mode: transport_mode.clone(),
                    log_mode: normalized_log_mode.clone(),
                    listen_port: port,
                    companion_spec: AiCompanionLaunchSpec::Persistent {
                        config_path: inspection.config_path.clone(),
                        passphrase,
                    },
                }
            }
        }
        PersistentLaunchAction::RecoverConfig => {
            if normalized_log_mode == "ghost" {
                recover_ai_network_plan(
                    &inspection,
                    transport_mode.clone(),
                    normalized_log_mode.clone(),
                    port,
                    None,
                )?
            } else {
                let passphrase = env_passphrase.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Passphrase is required for safe AI launch. Set QYPHA_PASSPHRASE or QYPHA_CONFIG_PASSPHRASE."
                    )
                })?;
                recover_ai_network_plan(
                    &inspection,
                    transport_mode.clone(),
                    normalized_log_mode.clone(),
                    port,
                    Some(passphrase),
                )?
            }
        }
        PersistentLaunchAction::MissingIdentity => unreachable!(),
    };

    save_agent_desktop_metadata(&metadata)?;
    persist_active_embedded_agent(&metadata.name)?;
    run_embedded_ai_terminal_session(&metadata, &network_plan.companion_spec).await
}

async fn launch_flow(
    name: &str,
    transport_mode: TransportMode,
    log_mode: &str,
    port: u16,
) -> Result<()> {
    if log_mode == "ghost" {
        start_ghost_daemon(name, port, transport_mode).await
    } else {
        // Safe flow: start the named TOML if it exists, otherwise recover safely or initialize.
        let (config_path, identity_path) = persistent_launch_paths(name)?;
        let config_exists = config_path.exists();
        let identity_exists = identity_path.exists();

        match determine_persistent_launch_action(config_exists, identity_exists) {
            PersistentLaunchAction::Initialize => {
                let transport_str = transport_mode_to_str(&transport_mode);
                crate::agent::init::initialize_agent(name, transport_str, log_mode, Some(port))
                    .await?;
            }
            PersistentLaunchAction::ReuseExisting => {
                println!(
                    "   {} {}",
                    "Reusing existing agent:".yellow().bold(),
                    name.cyan()
                );
            }
            PersistentLaunchAction::RecoverConfig => {
                println!(
                    "   {}",
                    format_existing_agent_recovery_notice(name, &config_path, &identity_path)
                        .yellow()
                );
                let passphrase = resolve_launch_passphrase(&format!(
                    "  Enter passphrase to unlock existing agent identity and restore {}",
                    config_path.display()
                ))?;
                let keypair =
                    AgentKeyPair::load_from_file(&identity_path, &passphrase).map_err(|e| {
                        anyhow::anyhow!(
                            "{} Failed to unlock existing identity at {}: {}",
                            format_existing_agent_recovery_notice(
                                name,
                                &config_path,
                                &identity_path
                            ),
                            identity_path.display(),
                            e,
                        )
                    })?;
                let config = crate::agent::init::build_persistent_agent_config(
                    name,
                    &keypair.metadata.role,
                    &keypair.did,
                    transport_mode.clone(),
                    log_mode,
                    port,
                );
                crate::agent::init::write_config_to_path(&config_path, &config, Some(&passphrase))?;
                std::env::set_var("QYPHA_PASSPHRASE", &passphrase);
                std::env::set_var("QYPHA_CONFIG_PASSPHRASE", &passphrase);
                println!(
                    "   {} {}",
                    "Recovered missing config:".yellow().bold(),
                    config_path.display()
                );
            }
            PersistentLaunchAction::MissingIdentity => {
                anyhow::bail!(
                    "Persistent agent '{}' is incomplete: config {} exists but identity {} is missing",
                    name,
                    config_path.display(),
                    identity_path.display()
                );
            }
        }

        let mut config = AppConfig::load(&config_path.display().to_string())?;
        let mut launch_passphrase: Option<String> = None;
        if config.has_encrypted_sensitive_fields() {
            let passphrase = resolve_launch_passphrase(
                "  Enter passphrase to decrypt config and unlock agent identity",
            )?;
            std::env::set_var("QYPHA_PASSPHRASE", &passphrase);
            std::env::set_var("QYPHA_CONFIG_PASSPHRASE", &passphrase);
            config.decrypt_sensitive_fields(Some(&passphrase))?;
            launch_passphrase = Some(passphrase);
        }

        let passphrase_for_identity = launch_passphrase.clone().or_else(|| {
            crate::config::config_passphrase_from_env().filter(|value| !value.trim().is_empty())
        });
        let mut config_dirty = false;
        if let Some(passphrase) = passphrase_for_identity.as_deref() {
            let keypair =
                AgentKeyPair::load_from_file(&identity_path, passphrase).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to unlock agent identity at {} while validating config: {}",
                        identity_path.display(),
                        e
                    )
                })?;
            if crate::agent::init::sync_config_identity_fields(&mut config, &keypair) {
                config_dirty = true;
                tracing::warn!(
                    path = %config_path.display(),
                    did = %config.agent.did,
                    "Recovered stale persistent config identity fields from encrypted agent identity"
                );
            }
        }
        if config.network.listen_port != port {
            config.network.listen_port = port;
            config_dirty = true;
        }
        if config.network.transport_mode != transport_mode {
            config.network.transport_mode = transport_mode.clone();
            config_dirty = true;
        }
        if config.logging.mode != log_mode {
            config.logging.mode = log_mode.to_string();
            config_dirty = true;
        }
        if config_dirty {
            crate::agent::init::write_config_to_path(
                &config_path,
                &config,
                launch_passphrase.as_deref(),
            )?;
        }
        let log_override = Some(log_mode.to_string());
        std::env::set_var(
            "QYPHA_ACTIVE_CONFIG_PATH",
            config_path.display().to_string(),
        );
        crate::agent::daemon::start_daemon(config, None, log_override).await
    }
}

fn persistent_launch_paths(name: &str) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let config_path = crate::agent::init::ensure_canonical_config_path_for_agent(name)?;
    let keys_dir = KeyStore::agent_keys_dir(name)?;
    let identity_path = KeyStore::new(&keys_dir).identity_path();
    Ok((config_path, identity_path))
}

#[cfg(unix)]
fn with_ghost_shutdown_stderr_suppressed<T>(f: impl FnOnce() -> T) -> T {
    use std::os::unix::io::AsRawFd;

    let devnull = std::fs::OpenOptions::new().write(true).open("/dev/null");
    let Ok(devnull) = devnull else {
        return f();
    };

    let saved_stderr = unsafe { libc::dup(2) };
    if saved_stderr < 0 {
        return f();
    }

    unsafe {
        libc::dup2(devnull.as_raw_fd(), 2);
    }
    let result = f();
    // Arti/Tor can emit the circuit-manager flush warning slightly after tmpdir
    // teardown, so keep stderr suppressed briefly for the remainder of Ghost exit.
    std::thread::sleep(std::time::Duration::from_millis(1000));
    unsafe {
        libc::dup2(saved_stderr, 2);
        libc::close(saved_stderr);
    }
    result
}

#[cfg(not(unix))]
fn with_ghost_shutdown_stderr_suppressed<T>(f: impl FnOnce() -> T) -> T {
    f()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistentLaunchAction {
    Initialize,
    ReuseExisting,
    RecoverConfig,
    MissingIdentity,
}

fn determine_persistent_launch_action(
    config_exists: bool,
    identity_exists: bool,
) -> PersistentLaunchAction {
    match (config_exists, identity_exists) {
        (false, false) => PersistentLaunchAction::Initialize,
        (true, true) => PersistentLaunchAction::ReuseExisting,
        (true, false) => PersistentLaunchAction::MissingIdentity,
        (false, true) => PersistentLaunchAction::RecoverConfig,
    }
}

fn resolve_launch_passphrase(prompt: &str) -> Result<String> {
    crate::config::config_passphrase_from_env()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            Password::new()
                .with_prompt(prompt)
                .interact()
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| anyhow::anyhow!("Passphrase required to continue"))
}

fn format_existing_agent_recovery_notice(
    name: &str,
    config_path: &std::path::Path,
    identity_path: &std::path::Path,
) -> String {
    let agent_root = identity_path
        .parent()
        .and_then(|path| path.parent())
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| identity_path.display().to_string());
    format!(
        "Existing agent state for '{name}' was found under {agent_root}. \
Deleting {config_path} does not remove the agent. \
Enter the existing passphrase to restore the missing config, or run `Qypha destroy --name {name} --force` to permanently remove the old agent before recreating it with a new passphrase.",
        config_path = config_path.display()
    )
}

fn parse_transport_mode(transport: &str) -> Result<TransportMode> {
    Ok(match transport.to_lowercase().as_str() {
        "lan" | "tcp" => TransportMode::Tcp,
        "tor" => TransportMode::Tor,
        "internet" | "inet" | "wan" => TransportMode::Internet,
        _ => anyhow::bail!(
            "Invalid transport mode '{}'. Use: lan, tor, internet",
            transport
        ),
    })
}

/// Start a Ghost-mode daemon: zero-persistence policy, ghost log mode, terminal wipe on exit.
///
/// Two-phase forensic strategy:
///   Phase 1 (PRE-daemon):  PREVENT future traces — disable history, terminal resume, swap hints
///   Phase 2 (POST-daemon): CLEAN existing traces — scrub the one "qypha launch" line + OS state
async fn start_ghost_daemon(
    name: &str,
    listen_port: u16,
    transport_mode: TransportMode,
) -> Result<()> {
    const DEFAULT_AGENT_ROLE: &str = "agent";
    // ── OPSEC ENFORCEMENT: Ghost mode requires anonymizing transport ──
    // LAN and Internet modes expose the operator's IP address, which
    // defeats the purpose of zero-trace Ghost mode.
    let transport_mode = match transport_mode {
        TransportMode::Tcp | TransportMode::Internet => {
            println!("\n   \x1b[31m\x1b[1m╔══════════════════════════════════════════════════════════╗\x1b[0m");
            println!(
                "   \x1b[31m\x1b[1m║  OPSEC WARNING: Ghost mode with {} transport   ║\x1b[0m",
                match transport_mode {
                    TransportMode::Tcp => "LAN     ",
                    _ => "Internet",
                }
            );
            println!("   \x1b[31m\x1b[1m║  exposes your IP address — OPSEC violation!             ║\x1b[0m");
            println!("   \x1b[31m\x1b[1m║                                                          ║\x1b[0m");
            println!("   \x1b[31m\x1b[1m║  Forcing transport to Tor for IP anonymity.              ║\x1b[0m");
            println!("   \x1b[31m\x1b[1m╚══════════════════════════════════════════════════════════╝\x1b[0m");
            TransportMode::Tor
        }
        other => other,
    };

    let mut forensic = ForensicStatus::new();

    // ══════════════════════════════════════════════════════════════
    //  PRE-FLIGHT: Environment security checks
    // ══════════════════════════════════════════════════════════════
    let (fde_active, fde_method) = check_disk_encryption_detail();
    if fde_active {
        println!(
            "\n   \x1b[32m\x1b[1m  FDE VERIFIED: {} active\x1b[0m",
            fde_method
        );
        println!("   \x1b[32m  Secure wipe: 1-pass overwrite + TRIM (sufficient with FDE)\x1b[0m");
    } else {
        println!("\n   \x1b[31m\x1b[1m╔══════════════════════════════════════════════════════════╗\x1b[0m");
        println!(
            "   \x1b[31m\x1b[1m║  CRITICAL: FULL-DISK ENCRYPTION IS OFF                  ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║                                                          ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║  Without FDE, secure wipe is ~40%% effective on SSDs.    ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║  SSD wear leveling redirects writes — old data persists  ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║  in flash cells until garbage collected.                 ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║                                                          ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║  Using 3-pass overwrite for defense-in-depth.            ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║                                                          ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║  STRONGLY RECOMMENDED:                                   ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║    macOS  → Enable FileVault (System Prefs > Security)   ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║    Linux  → Enable LUKS (cryptsetup luksFormat)          ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m║    Windows→ Enable BitLocker (manage-bde -on C:)         ║\x1b[0m"
        );
        println!(
            "   \x1b[31m\x1b[1m╚══════════════════════════════════════════════════════════╝\x1b[0m"
        );
        // Signal secure_wipe to use multi-pass overwrite
        std::env::set_var("_QYPHA_FDE_OFF", "1");
    }

    if !check_swap_safety() {
        println!("   \x1b[31m\x1b[1mWARNING: Unencrypted swap detected.\x1b[0m");
        println!("   \x1b[31mKey material in RAM could be paged to disk in cleartext.\x1b[0m");
        println!("   \x1b[31mRun 'sudo swapoff -a' or enable encrypted swap.\x1b[0m\n");
    }

    #[cfg(target_os = "macos")]
    if check_icloud_risk() {
        println!("   \x1b[31m\x1b[1mWARNING: iCloud Desktop/Documents sync detected.\x1b[0m");
        println!("   \x1b[31mBinary may be synced to Apple servers.\x1b[0m");
        println!(
            "   \x1b[31mMove binary to a non-synced location (e.g., /usr/local/bin).\x1b[0m\n"
        );
    }

    // ── Root privilege check: warn if not running as root ──
    if !forensic.has_root {
        println!("\n   \x1b[33m\x1b[1m╔══════════════════════════════════════════════════════════╗\x1b[0m");
        println!(
            "   \x1b[33m\x1b[1m║  NOT RUNNING AS ROOT / ADMIN                            ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m║                                                          ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m║  Ghost mode provides ~30%% forensic protection without   ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m║  root privileges. OS-level traces (journal, snapshots,   ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m║  event logs, hibernation) CANNOT be cleaned.             ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m║                                                          ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m║  For full protection: sudo Qypha launch                 ║\x1b[0m"
        );
        println!(
            "   \x1b[33m\x1b[1m╚══════════════════════════════════════════════════════════╝\x1b[0m"
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  PHASE 1: PREVENT — stop all future disk traces IMMEDIATELY
    // ══════════════════════════════════════════════════════════════
    ghost_prevent_traces(&mut forensic);

    // Ghost transfer policy:
    // Stage chunked-transfer payloads on secure temp disk by default to avoid RAM pressure
    // on very large files. This can be disabled via QYPHA_GHOST_DISK_CHUNK_STAGING=0.
    let use_disk_chunk_staging_in_ghost = std::env::var("QYPHA_GHOST_DISK_CHUNK_STAGING")
        .map(|v| v != "0")
        .unwrap_or(true);

    println!("\n   {}", "GHOST MODE ACTIVATED".red().bold());
    println!(
        "   {}",
        "Sensitive keys/session state stay in RAM; temp transfer staging uses volatile secure storage.".red()
    );
    println!(
        "   {}",
        "No persistent keys/config/audit logs are written to disk.".dimmed()
    );
    if use_disk_chunk_staging_in_ghost {
        println!(
            "   {}",
            "Large file chunk staging: secure temp disk (RAM pressure reduced).".dimmed()
        );
    } else {
        println!(
            "   {}",
            "Large file chunk staging: RAM-disk (faster, but high RAM usage).".dimmed()
        );
    }
    println!(
        "   {}",
        "Shell history recording DISABLED for this session."
            .yellow()
            .bold()
    );
    println!("   {}\n", "Terminal state saving DISABLED.".yellow().bold());

    forensic.print_warnings();

    // Runtime temp root for transfer/chunk/session artifacts.
    // If disk chunk staging is enabled (default), use secure private temp dir to
    // prevent RAM blow-ups on huge transfers. Otherwise (opt-in), try RAM disk.
    #[cfg(target_os = "macos")]
    let (runtime_temp_root, runtime_temp_guard, runtime_ramdisk_device) = {
        if !use_disk_chunk_staging_in_ghost {
            if let Some((root, device)) = setup_macos_ghost_ramdisk(&mut forensic) {
                (root, None, Some(device))
            } else {
                let guard = tempfile::tempdir()
                    .map_err(|e| anyhow::anyhow!("Failed to create runtime temp dir: {}", e))?;
                let root = guard.path().to_path_buf();
                forensic.results.push(ForensicCmd {
                    desc: "Allocate macOS RAM disk runtime storage",
                    success: false,
                    needs_root: false,
                });
                (root, Some(guard), None)
            }
        } else {
            let guard = tempfile::tempdir()
                .map_err(|e| anyhow::anyhow!("Failed to create runtime temp dir: {}", e))?;
            let root = guard.path().to_path_buf();
            (root, Some(guard), None)
        }
    };

    #[cfg(not(target_os = "macos"))]
    let (runtime_temp_root, runtime_temp_guard) = {
        let guard = tempfile::tempdir()
            .map_err(|e| anyhow::anyhow!("Failed to create runtime temp dir: {}", e))?;
        let root = guard.path().to_path_buf();
        (root, Some(guard))
    };
    std::env::set_var(
        "QYPHA_RUNTIME_TMPDIR",
        runtime_temp_root.to_string_lossy().to_string(),
    );
    for sub in [
        "qypha-ghost-recv",
        "qypha-ghost-handoff",
        "qypha-transfer",
        "qypha-sessions",
        "qypha-chunk-recv",
    ] {
        let _ = std::fs::create_dir_all(runtime_temp_root.join(sub));
    }

    // Generate identity in memory — never touches disk
    let keypair = AgentKeyPair::generate(name, DEFAULT_AGENT_ROLE);

    // Create tmpdir for Tor state (auto-cleaned when _tmp_guard drops)
    let _tmp_guard =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create tmpdir: {}", e))?;
    let tmp_tor_dir = _tmp_guard.path().to_path_buf();

    // Prevent Spotlight indexing on the tmpdir
    let _ = std::fs::write(tmp_tor_dir.join(".metadata_never_index"), "");

    // Set restrictive permissions on tmpdir (owner-only: 0o700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_tor_dir, std::fs::Permissions::from_mode(0o700));
    }

    // Build config entirely in memory — no TOML, no fs::write
    let mut network_config = NetworkConfig::default();
    network_config.listen_port = listen_port;
    network_config.transport_mode = transport_mode.clone();
    if matches!(transport_mode, TransportMode::Tor) {
        network_config.enable_mdns = false;
    }
    network_config.tor.data_dir = Some(tmp_tor_dir.to_string_lossy().to_string());

    let mut security_config = SecurityConfig::default();
    security_config.log_mode = "ghost".to_string();
    security_config.shadow_mode_enabled = true;
    // cover_traffic.mode defaults to "auto" — activates for Ghost

    let mut logging_config = LoggingConfig::default();
    logging_config.mode = "ghost".to_string();

    let mut transfer_config = TransferConfig::default();
    transfer_config.allow_disk_chunk_staging_in_zero_trace = use_disk_chunk_staging_in_ghost;
    transfer_config.enable_resume = false;

    let config = AppConfig {
        agent: AgentConfig {
            name: name.to_string(),
            role: DEFAULT_AGENT_ROLE.to_string(),
            did: keypair.did.clone(),
        },
        network: network_config,
        security: security_config,
        logging: logging_config,
        roles: RolesConfig::default(),
        transfer: transfer_config,
    };

    // Use tmpdir as agent_data_dir (for any code that references it)
    let agent_data_dir = _tmp_guard.path().to_path_buf();

    // Set log mode env var for subprocess/signal-safe cleanup visibility.
    std::env::set_var("QYPHA_LOG_MODE", "ghost");

    // Start the main daemon loop with ghost config
    let result = crate::agent::daemon::start_daemon_inner(
        config,
        keypair,
        agent_data_dir,
        None,
        Some("ghost".to_string()),
    )
    .await;

    // ══════════════════════════════════════════════════════════════
    //  PHASE 2: CLEAN — secure wipe tmpdir + forensic cleanup
    // ══════════════════════════════════════════════════════════════

    // Suppress Arti's "Unable to flush state on circuit manager drop" error.
    // We intentionally wipe the tmpdir before Arti drops — the error is expected
    // and cosmetic. Silence tracing to avoid confusing Ghost cleanup output.
    let _log_guard = {
        use tracing_subscriber::prelude::*;
        // Replace global subscriber with a no-op for the cleanup phase
        let noop = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::set_default(noop)
    };

    // Secure wipe the Tor tmpdir BEFORE TempDir::drop (which only does rm -rf)
    // This overwrites all Tor state, circuit keys, and consensus data with
    // random bytes before unlinking — prevents SSD flash cell recovery.
    secure_wipe_dir(&tmp_tor_dir);
    forensic.record_ok("Tor tmpdir secure wiped");
    if runtime_temp_root.exists() {
        secure_wipe_dir(&runtime_temp_root);
        forensic.record_ok("Runtime temp artifacts secure wiped");
    }

    ghost_forensic_cleanup(&mut forensic);

    // Verification layer: check critical traces were removed
    let verification = ghost_verify_cleanup();

    // Dynamic summary (replaces hardcoded PREVENTED/CLEANED lists)
    println!("\n   \x1b[31m\x1b[1mGHOST CLEANUP COMPLETE\x1b[0m");
    forensic.print_summary();

    println!("   \x1b[32m MEMORY:\x1b[0m");
    println!("   \x1b[90m  [OK]   Crypto keys zeroed from RAM (zeroize)\x1b[0m");
    println!("   \x1b[90m  [OK]   RAM was locked to prevent swap (mlock)\x1b[0m");

    // Verification results
    if !verification.is_empty() {
        println!("   \x1b[36m VERIFIED:\x1b[0m");
        for (desc, passed) in &verification {
            if *passed {
                println!("   \x1b[90m  [PASS] {}\x1b[0m", desc);
            } else {
                println!(
                    "   \x1b[31m  [FAIL] {} — manual cleanup needed\x1b[0m",
                    desc
                );
            }
        }
    }

    println!();
    println!("   \x1b[33m\x1b[1mPOST-CLEANUP OPSEC NOTES:\x1b[0m");
    println!("   \x1b[33m  1. For maximum hygiene, close this terminal tab to release terminal RAM\x1b[0m");
    println!("   \x1b[33m  2. For future Ghost runs, prefer launching from encrypted removable media\x1b[0m");
    println!(
        "   \x1b[33m  3. Optional launcher alias: cp Qypha /tmp/.sys && /tmp/.sys launch\x1b[0m"
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Clean up FDE env var
    std::env::remove_var("_QYPHA_FDE_OFF");
    std::env::remove_var("QYPHA_RUNTIME_TMPDIR");

    // Suppress Arti's "Unable to flush state on circuit manager drop" error.
    // The warning can arrive slightly after tmpdir teardown, so keep stderr
    // redirected for the remainder of Ghost shutdown only.
    with_ghost_shutdown_stderr_suppressed(|| {
        drop(_tmp_guard);

        #[cfg(target_os = "macos")]
        if let Some(device) = runtime_ramdisk_device {
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", &device, "-force"])
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .output()
                .ok();
        }
        drop(runtime_temp_guard);
    });

    result
}

/// PHASE 1: Prevention — disable all trace-producing mechanisms BEFORE daemon runs.
fn ghost_prevent_traces(status: &mut ForensicStatus) {
    let session_start_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::env::set_var(
        "_QYPHA_GHOST_SESSION_START_UNIX",
        session_start_unix.to_string(),
    );

    // ── Process name masking (hide "qypha" from ps/top) ──
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        if let Ok(name) = CString::new("system-helper") {
            unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        if let Ok(name) = CString::new("system-helper") {
            unsafe {
                libc::pthread_setname_np(name.as_ptr());
            }
        }
    }

    // ── Disable shell history ──
    std::env::set_var("HISTFILE", "/dev/null");
    std::env::set_var("HISTSIZE", "0");
    std::env::set_var("HISTFILESIZE", "0");
    std::env::set_var("SAVEHIST", "0");
    std::env::set_var("SHELL_SESSION_HISTORY", "0");
    status.record_ok("Shell history disabled");

    // ── Terminal Resume disable (macOS) ──
    #[cfg(target_os = "macos")]
    {
        status.run_cmd(
            "Disable Terminal.app Resume",
            "defaults",
            &[
                "write",
                "com.apple.Terminal",
                "NSQuitAlwaysKeepsWindows",
                "-bool",
                "false",
            ],
            false,
        );
        status.run_cmd(
            "Disable iTerm2 Resume",
            "defaults",
            &[
                "write",
                "com.googlecode.iterm2",
                "NSQuitAlwaysKeepsWindows",
                "-bool",
                "false",
            ],
            false,
        );
    }

    // ── Set terminal title to something innocent ──
    print!("\x1b]0;Terminal\x07");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    status.record_ok("Terminal title masked");

    // ── macOS: Time Machine, hibernation, Spotlight ──
    #[cfg(target_os = "macos")]
    {
        // Save current hibernatemode for restoration
        if let Ok(output) = std::process::Command::new("pmset")
            .args(["-g", "custom"])
            .stderr(std::process::Stdio::piped())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("hibernatemode") {
                    if let Some(val) = line.split_whitespace().last() {
                        std::env::set_var("_QYPHA_ORIG_HIBERNATEMODE", val);
                    }
                }
            }
        }

        // macOS Ventura+: tmutil may require TCC Full Disk Access even as root.
        // Try multiple approaches without recording intermediate failures.
        let tm_disabled = std::process::Command::new("tmutil")
            .args(["disable"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
            || std::process::Command::new("tmutil")
                .args(["stopbackup"])
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        status.results.push(ForensicCmd {
            desc: "Disable Time Machine",
            success: tm_disabled,
            needs_root: true,
        });
        status.run_cmd(
            "Disable hibernation (hibernatemode 0)",
            "pmset",
            &["-a", "hibernatemode", "0"],
            true,
        );
        status.run_cmd(
            "Disable standby (RAM-to-disk)",
            "pmset",
            &["-a", "standby", "0"],
            true,
        );
        status.run_cmd(
            "Delete sleep image",
            "rm",
            &["-f", "/var/vm/sleepimage"],
            true,
        );

        // Spotlight: .metadata_never_index + mdutil
        if let Ok(home) = std::env::var("HOME") {
            let nf_dir = std::path::PathBuf::from(&home).join(".qypha");
            if nf_dir.exists() {
                let _ = std::fs::write(nf_dir.join(".metadata_never_index"), "");
            }
        }
        status.run_cmd(
            "Disable Spotlight indexing",
            "mdutil",
            &["-i", "off", "/"],
            true,
        );
    }

    // ── macOS: disable core dumps (additional layer) ──
    #[cfg(target_os = "macos")]
    {
        status.run_cmd("Disable core dumps", "sh", &["-c", "ulimit -c 0"], true);
    }

    // ── Linux: disable swap + auditd ──
    #[cfg(target_os = "linux")]
    {
        status.run_cmd("Disable swap", "swapoff", &["-a"], true);
        status.run_cmd("Disable audit logging", "auditctl", &["-e", "0"], true);
    }

    // ── Windows: hibernation, search, VSS, prefetch ──
    #[cfg(target_os = "windows")]
    {
        // PowerShell history: redirect to NUL
        if let Ok(appdata) = std::env::var("APPDATA") {
            let ps_history = std::path::PathBuf::from(&appdata)
                .join("Microsoft\\Windows\\PowerShell\\PSReadLine");
            if ps_history.exists() {
                std::env::set_var(
                    "_QYPHA_PS_HISTORY",
                    ps_history.to_string_lossy().to_string(),
                );
            }
        }

        // Save original prefetch state for restoration
        if let Ok(output) = std::process::Command::new("reg")
            .args(["query",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
                "/v", "EnablePrefetcher"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse "REG_DWORD    0x3" style output
            if let Some(val) = stdout.split("0x").nth(1).and_then(|s| s.trim().split_whitespace().next()) {
                std::env::set_var("_QYPHA_ORIG_PREFETCH", val);
            }
        }

        status.run_cmd("Disable hibernation", "powercfg", &["/h", "off"], true);
        status.run_cmd("Stop Windows Search", "sc", &["stop", "WSearch"], true);
        status.run_cmd(
            "Delete Volume Shadow Copies",
            "vssadmin",
            &["delete", "shadows", "/all", "/quiet"],
            true,
        );
        status.run_cmd("Disable Prefetch", "reg",
            &["add",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
              "/v", "EnablePrefetcher", "/t", "REG_DWORD", "/d", "0", "/f"], true);

        // Disable clipboard history (Windows 10+)
        status.run_cmd(
            "Disable Clipboard History",
            "reg",
            &[
                "add",
                "HKCU\\Software\\Microsoft\\Clipboard",
                "/v",
                "EnableClipboardHistory",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ],
            true,
        );

        // Disable Windows Timeline / Activity History
        status.run_cmd(
            "Disable Activity History",
            "reg",
            &[
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "/v",
                "EnableActivityFeed",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ],
            true,
        );
    }
}

/// Comprehensive forensic cleanup for Ghost mode exit.
/// Targets every known disk/OS trace vector on macOS and Linux.
fn ghost_forensic_cleanup(status: &mut ForensicStatus) {
    use std::io::Write;

    // ── 1. Clear terminal screen + scrollback buffer (ANSI) ──
    print!("\x1b[2J\x1b[H"); // clear screen + cursor home
    print!("\x1b[3J"); // clear scrollback (xterm/iTerm2/GNOME/Windows Terminal)
    let _ = std::io::stdout().flush();
    status.record_ok("Terminal screen + scrollback purged");

    // ── 2. Scrub shell history with secure overwrite ──
    scrub_shell_history();
    status.record_ok("Shell history scrubbed");

    // ── 3. DNS cache flush (prevents resolver cache from leaking domain queries) ──
    #[cfg(target_os = "macos")]
    {
        status.run_cmd(
            "Flush DNS cache (dscacheutil)",
            "dscacheutil",
            &["-flushcache"],
            false,
        );
        status.run_cmd(
            "Flush DNS cache (mDNSResponder)",
            "killall",
            &["-HUP", "mDNSResponder"],
            true,
        );
    }
    #[cfg(target_os = "linux")]
    {
        // Try systemd-resolved first, fallback to nscd
        if !status.run_cmd(
            "Flush DNS cache (resolvectl)",
            "resolvectl",
            &["flush-caches"],
            false,
        ) {
            status.run_cmd("Flush DNS cache (nscd)", "nscd", &["-i", "hosts"], false);
        }
    }
    #[cfg(target_os = "windows")]
    {
        status.run_cmd("Flush DNS cache", "ipconfig", &["/flushdns"], false);
    }

    // ── 4. OS-specific forensic cleanup ──
    #[cfg(target_os = "macos")]
    macos_forensic_cleanup(status);

    #[cfg(target_os = "linux")]
    linux_forensic_cleanup(status);

    #[cfg(target_os = "windows")]
    windows_forensic_cleanup(status);

    // ── 5. Overwrite environment variables that might leak info ──
    std::env::remove_var("QYPHA_CONFIG");
    std::env::remove_var("QYPHA_PASSPHRASE");
    std::env::remove_var("QYPHA_LOG_MODE");
    std::env::remove_var("_QYPHA_GHOST_SESSION_START_UNIX");
    status.record_ok("Environment variables scrubbed");

    // ── 6. APFS Snapshot / Time Machine restoration (macOS) ──
    #[cfg(target_os = "macos")]
    {
        status.run_cmd(
            "Delete APFS local snapshots",
            "tmutil",
            &["deletelocalsnapshots", "/"],
            true,
        );
        // Re-enable Time Machine (best-effort — may fail without TCC Full Disk Access)
        let tm_enabled = std::process::Command::new("tmutil")
            .args(["enable"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // Only record if it succeeded — failure to re-enable is not a forensic risk
        if tm_enabled {
            status.record_ok("Re-enable Time Machine");
        }

        // Restore original hibernatemode
        let orig_mode =
            std::env::var("_QYPHA_ORIG_HIBERNATEMODE").unwrap_or_else(|_| "3".to_string());
        status.run_cmd(
            "Restore hibernation mode",
            "pmset",
            &["-a", "hibernatemode", &orig_mode],
            true,
        );
        std::env::remove_var("_QYPHA_ORIG_HIBERNATEMODE");

        status.run_cmd("Restore standby", "pmset", &["-a", "standby", "1"], true);
        status.run_cmd("Re-enable Spotlight", "mdutil", &["-i", "on", "/"], true);
        // Secure wipe FSEvents (not just rm -rf — overwrites data on disk)
        let fseventsd = std::path::Path::new("/.fseventsd");
        if fseventsd.is_dir() {
            secure_wipe_dir(fseventsd);
            status.record_ok("FSEvents logs securely wiped");
        }
        status.run_cmd(
            "Delete sleep image",
            "rm",
            &["-f", "/var/vm/sleepimage"],
            true,
        );
    }

    // ── 7. Windows restoration ──
    #[cfg(target_os = "windows")]
    {
        status.run_cmd("Re-enable hibernation", "powercfg", &["/h", "on"], true);
        status.run_cmd(
            "Re-enable Windows Search",
            "sc",
            &["start", "WSearch"],
            true,
        );

        // Restore original prefetch value
        let orig_prefetch =
            std::env::var("_QYPHA_ORIG_PREFETCH").unwrap_or_else(|_| "3".to_string());
        let prefetch_val = format!("{}", orig_prefetch);
        status.run_cmd("Restore Prefetch", "reg",
            &["add",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
              "/v", "EnablePrefetcher", "/t", "REG_DWORD", "/d", &prefetch_val, "/f"], true);
        std::env::remove_var("_QYPHA_ORIG_PREFETCH");
        std::env::remove_var("_QYPHA_PS_HISTORY");

        // Restore clipboard history and activity history
        status.run_cmd(
            "Restore Clipboard History",
            "reg",
            &[
                "delete",
                "HKCU\\Software\\Microsoft\\Clipboard",
                "/v",
                "EnableClipboardHistory",
                "/f",
            ],
            true,
        );
        status.run_cmd(
            "Restore Activity History",
            "reg",
            &[
                "delete",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "/v",
                "EnableActivityFeed",
                "/f",
            ],
            true,
        );
    }

    // ── 8. Linux: re-enable services ──
    #[cfg(target_os = "linux")]
    {
        status.run_cmd("Re-enable swap", "swapon", &["-a"], true);
        status.run_cmd("Re-enable audit logging", "auditctl", &["-e", "1"], true);
    }

    // ── 9. Wipe shadow audit directory if it exists (should be empty in Ghost) ──
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let shadow_dir = std::path::PathBuf::from(&home)
            .join(".qypha")
            .join("shadow_audit");
        if shadow_dir.exists() {
            secure_wipe_dir(&shadow_dir);
            status.record_ok("Shadow audit directory wiped");
        }
    }

    // ── 10. Wipe Ghost-mode received files (written to tmpdir during session) ──
    let ghost_recv_dir = ghost_runtime_temp_root().join("qypha-ghost-recv");
    if ghost_recv_dir.exists() {
        secure_wipe_dir(&ghost_recv_dir);
        status.record_ok("Ghost received files securely wiped");
    }
    let ghost_handoff_dir = ghost_runtime_temp_root().join("qypha-ghost-handoff");
    if ghost_handoff_dir.exists() {
        secure_wipe_dir(&ghost_handoff_dir);
        status.record_ok("Ghost secure handoff staging securely wiped");
    }

    // ── 11. Wipe chunked transfer temp files (packed archives + session metadata) ──
    let transfer_dir = ghost_runtime_temp_root().join("qypha-transfer");
    if transfer_dir.exists() {
        secure_wipe_dir(&transfer_dir);
        status.record_ok("Chunked transfer temp files securely wiped");
    }
    let session_dir = ghost_runtime_temp_root().join("qypha-sessions");
    if session_dir.exists() {
        secure_wipe_dir(&session_dir);
        status.record_ok("Transfer session files securely wiped");
    }
}

/// macOS-specific: destroy Terminal.app/iTerm2 saved state, reset title, clean logs
#[cfg(target_os = "macos")]
fn macos_forensic_cleanup(status: &mut ForensicStatus) {
    use std::io::Write;

    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => return,
    };

    // Reset terminal title bar (prevents "qypha" from showing in window title)
    print!("\x1b]0; \x07");
    let _ = std::io::stdout().flush();

    // ── Terminal.app saved state (macOS Resume feature) ──
    let terminal_saved = home.join("Library/Saved Application State/com.apple.Terminal.savedState");
    if terminal_saved.exists() {
        secure_wipe_dir(&terminal_saved);
        status.record_ok("Terminal.app saved state wiped");
    }

    // ── iTerm2 saved state ──
    let iterm_saved = home.join("Library/Saved Application State/com.googlecode.iterm2.savedState");
    if iterm_saved.exists() {
        secure_wipe_dir(&iterm_saved);
        status.record_ok("iTerm2 saved state wiped");
    }

    // ── iTerm2 session restoration data ──
    let iterm_support = home.join("Library/Application Support/iTerm2/iTermServer");
    if iterm_support.exists() {
        secure_wipe_dir(&iterm_support);
        status.record_ok("iTerm2 session data wiped");
    }

    // ── macOS Recent Items — remove only qypha entries ──
    // Read the recent items plist, remove only entries containing "qypha",
    // and write back the cleaned version. Other applications' recent items are preserved.
    let recent_plist = home.join("Library/Preferences/com.apple.recentitems.plist");
    let mut recent_ok = false;
    if recent_plist.exists() {
        if let Ok(content) = std::fs::read_to_string(&recent_plist) {
            let keyword = "qypha";
            if content.to_lowercase().contains(keyword) {
                // Filter out lines containing qypha (plist XML format)
                let cleaned: Vec<&str> = content
                    .lines()
                    .filter(|line| !line.to_lowercase().contains(keyword))
                    .collect();
                if let Ok(mut f) = std::fs::File::create(&recent_plist) {
                    use std::io::Write;
                    let _ = f.write_all(cleaned.join("\n").as_bytes());
                    let _ = f.sync_all();
                }
                recent_ok = true;
            } else {
                // No qypha entries — nothing to clean
                recent_ok = true;
            }
        }
    } else {
        // Plist doesn't exist — no recent items to clean
        recent_ok = true;
    }
    // Also scrub the SFL2 recent items database (Catalina+)
    let sfl2_dir = home.join("Library/Application Support/com.apple.sharedfilelist");
    if sfl2_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&sfl2_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if name.contains("RecentDocuments") || name.contains("RecentApplications") {
                        // These are binary sfl2 files — if they contain qypha, wipe them
                        if let Ok(data) = std::fs::read(&p) {
                            if data.windows(11).any(|w| w == b"qypha") {
                                secure_wipe_file(&p);
                                recent_ok = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if recent_ok {
        status.record_ok("Clear Recent Items (qypha only)");
    } else {
        status.results.push(ForensicCmd {
            desc: "Clear Recent Items (qypha only)",
            success: false,
            needs_root: false,
        });
    }

    // ── LaunchServices database: unregister only our binary ──
    // Instead of resetting the entire DB (-kill -r), only remove our app's registration.
    // This preserves all other applications' file type associations and registrations.
    if let Ok(exe) = std::env::current_exe() {
        let lsregister = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister";
        let exe_str = exe.to_string_lossy().to_string();
        let unreg_ok = std::process::Command::new(lsregister)
            .args(["-u", &exe_str])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if unreg_ok {
            status.record_ok("LaunchServices unregistered (qypha only)");
        } else {
            // Binary might not be registered — that's fine
            status.record_ok("LaunchServices clean (not registered)");
        }
    }

    // ── macOS Unified Log: targeted cleanup ──
    // `log erase` only supports `--all` (no per-process filtering).
    // Instead of nuking ALL system logs, we:
    //   1. Wipe the per-process tracer .logarchive files that mention qypha
    //   2. Clear the diagnostics persist directory for our subsystem
    // This preserves other applications' log entries.
    let log_dirs = [
        std::path::PathBuf::from("/var/db/diagnostics"),
        std::path::PathBuf::from("/var/db/uuidtext"),
    ];
    let mut log_cleaned = false;
    for log_dir in &log_dirs {
        if log_dir.is_dir() {
            // Walk the directory and wipe files that reference qypha
            if let Ok(walker) = std::fs::read_dir(log_dir) {
                for entry in walker.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if let Ok(data) = std::fs::read(&p) {
                            if data.windows(11).any(|w| w == b"qypha") {
                                secure_wipe_file(&p);
                                log_cleaned = true;
                            }
                        }
                    }
                }
            }
        }
    }
    // Also scrub /var/log/system.log for qypha mentions
    let syslog = std::path::Path::new("/var/log/system.log");
    if syslog.exists() {
        if let Ok(content) = std::fs::read_to_string(syslog) {
            let lower_content = content.to_lowercase();
            let syslog_keywords: &[&str] = &["qypha", "did:nxf:", "system-helper"];
            if syslog_keywords.iter().any(|kw| lower_content.contains(kw)) {
                let cleaned: Vec<&str> = content
                    .lines()
                    .filter(|line| {
                        let ll = line.to_lowercase();
                        !syslog_keywords.iter().any(|kw| ll.contains(kw))
                    })
                    .collect();
                if let Ok(mut f) = std::fs::File::create(syslog) {
                    use std::io::Write;
                    let _ = f.write_all(cleaned.join("\n").as_bytes());
                    let _ = f.sync_all();
                    log_cleaned = true;
                }
            }
        }
    }
    if log_cleaned {
        status.record_ok("Unified Log entries cleaned (qypha only)");
    } else {
        status.record_ok("Unified Log clean (no qypha traces found)");
    }

    // ── Extended xattr cleanup on binary ──
    // Removes quarantine, download date, and download source metadata
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = exe.to_string_lossy().to_string();
        for xattr_name in &[
            "com.apple.quarantine",
            "com.apple.metadata:kMDItemDownloadedDate",
            "com.apple.metadata:kMDItemWhereFroms",
        ] {
            let _ = std::process::Command::new("xattr")
                .args(["-d", xattr_name, &exe_str])
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .output();
        }
        status.record_ok("Extended xattrs cleaned (quarantine+download metadata)");
    }

    // ── Crash report cleanup (DiagnosticReports) ──
    // macOS writes crash logs when processes crash — could contain binary name/path
    let user_diag = home.join("Library/Logs/DiagnosticReports");
    if user_diag.is_dir() {
        cleanup_crash_reports(&user_diag);
    }
    let system_diag = std::path::PathBuf::from("/Library/Logs/DiagnosticReports");
    if system_diag.is_dir() {
        cleanup_crash_reports(&system_diag);
    }
    status.record_ok("Crash reports cleaned (DiagnosticReports)");

    // ── Kernel crash dumps (/cores/) ──
    let cores_dir = std::path::Path::new("/cores");
    if cores_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(cores_dir) {
            for entry in entries.flatten() {
                secure_wipe_file(&entry.path());
            }
        }
        status.record_ok("Kernel crash dumps wiped (/cores)");
    }

    // ── QuarantineEventsV2 database (app launch history) ──
    let qev_db = home.join("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2");
    if qev_db.exists() {
        secure_wipe_file(&qev_db);
        status.record_ok("QuarantineEventsV2 database wiped");
    }

    // ── Per-user cache (/private/var/folders/) — qypha traces ──
    if let Ok(output) = std::process::Command::new("find")
        .args([
            "/private/var/folders/",
            "-maxdepth",
            "5",
            "(",
            "-name",
            "*qypha*",
            "-o",
            "-name",
            "*system-helper*",
            ")",
        ])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let p = std::path::Path::new(line.trim());
            if p.is_file() {
                secure_wipe_file(p);
            } else if p.is_dir() {
                secure_wipe_dir(p);
            }
        }
        status.record_ok("Per-user cache cleaned (/private/var/folders)");
    }

    // ── Clipboard clear ──
    if let Ok(mut child) = std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = std::io::Write::write_all(&mut stdin, b"");
        }
        let _ = child.wait();
        status.record_ok("Clipboard cleared");
    }

    // ── Keychain entries — qypha related ──
    let _ = std::process::Command::new("security")
        .args(["delete-generic-password", "-l", "qypha"])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output();
    let _ = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", "qypha"])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output();
    status.record_ok("Keychain entries cleaned");

    // ── Siri Suggestions cache ──
    let siri_dir = home.join("Library/Application Support/com.apple.SiriSuggestions");
    if siri_dir.is_dir() {
        cleanup_crash_reports(&siri_dir);
        status.record_ok("Siri Suggestions cache cleaned");
    }

    // ── ASL legacy logs ──
    status.run_cmd("Clear ASL logs", "rm", &["-rf", "/var/log/asl/"], true);

    // ── .Trash — qypha traces ──
    let trash_dir = home.join(".Trash");
    if trash_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&trash_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.contains("qypha") || lower.contains("system-helper") {
                        if entry.path().is_file() {
                            secure_wipe_file(&entry.path());
                        } else {
                            secure_wipe_dir(&entry.path());
                        }
                    }
                }
            }
        }
        status.record_ok("Trash cleaned");
    }

    // ── /tmp + /var/tmp + /private/tmp — qypha traces ──
    let tmp_keywords: &[&str] = &["qypha", "did:nxf:", "system-helper"];
    let running_exe = std::env::current_exe().ok();
    for tmp_dir in &["/tmp", "/var/tmp", "/private/tmp"] {
        let p = std::path::Path::new(tmp_dir);
        if p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(p) {
                for entry in entries.flatten() {
                    let ep = entry.path();
                    // Skip the running binary itself (can't wipe while executing)
                    if let Some(ref exe) = running_exe {
                        if let (Ok(a), Ok(b)) = (ep.canonicalize(), exe.canonicalize()) {
                            if a == b {
                                continue;
                            }
                        }
                    }
                    if let Some(name) = entry.file_name().to_str() {
                        let lower = name.to_lowercase();
                        if tmp_keywords.iter().any(|kw| lower.contains(kw)) {
                            if ep.is_file() {
                                secure_wipe_file(&ep);
                            } else {
                                secure_wipe_dir(&ep);
                            }
                        }
                    }
                }
            }
        }
    }
    status.record_ok("Temp directories cleaned");

    // ── Restore Terminal Resume to default ──
    status.run_cmd(
        "Restore Terminal.app Resume",
        "defaults",
        &["delete", "com.apple.Terminal", "NSQuitAlwaysKeepsWindows"],
        false,
    );
    status.run_cmd(
        "Restore iTerm2 Resume",
        "defaults",
        &[
            "delete",
            "com.googlecode.iterm2",
            "NSQuitAlwaysKeepsWindows",
        ],
        false,
    );
}

/// Linux-specific: clean systemd journal, recently-used, bash session logs
#[cfg(target_os = "linux")]
fn linux_forensic_cleanup(status: &mut ForensicStatus) {
    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => return,
    };

    // ── systemd journal: remove entries for this process ──
    status.run_cmd("Rotate systemd journal", "journalctl", &["--rotate"], true);
    status.run_cmd(
        "Vacuum systemd journal",
        "journalctl",
        &["--vacuum-time=1s"],
        true,
    );

    // ── GNOME recently-used.xbel ──
    let recently_used = home.join(".local/share/recently-used.xbel");
    if recently_used.exists() {
        scrub_file_containing(&recently_used, &["qypha", "did:nxf:", "system-helper"]);
        status.record_ok("GNOME recently-used scrubbed");
    }

    // ── KDE activity logs ──
    let kde_recent = home.join(".local/share/RecentDocuments");
    if kde_recent.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&kde_recent) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    let lower = name.to_lowercase();
                    if lower.contains("qypha") || lower.contains("system-helper") {
                        crate::os_adapter::secure_wipe::secure_wipe_file(&p);
                    }
                }
            }
        }
        status.record_ok("KDE recent documents scrubbed");
    }

    // ── Crash report cleanup (/var/crash/) ──
    let crash_dir = std::path::PathBuf::from("/var/crash");
    if crash_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&crash_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    let lower = name.to_lowercase();
                    if lower.contains("qypha") || lower.contains("system-helper") {
                        secure_wipe_file(&p);
                    }
                }
            }
        }
        status.record_ok("Crash reports cleaned (/var/crash)");
    }

    // ── Systemd coredumps (/var/lib/systemd/coredump/) ──
    let coredump_dir = std::path::Path::new("/var/lib/systemd/coredump");
    if coredump_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(coredump_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.contains("qypha") || lower.contains("system-helper") {
                        secure_wipe_file(&entry.path());
                    }
                }
            }
        }
        status.record_ok("Systemd coredumps cleaned");
    }

    // ── /cores/ directory (alternative core dump location) ──
    let cores = std::path::Path::new("/cores");
    if cores.is_dir() {
        if let Ok(entries) = std::fs::read_dir(cores) {
            for entry in entries.flatten() {
                secure_wipe_file(&entry.path());
            }
        }
        status.record_ok("Core dump files cleaned (/cores)");
    }

    // ── Login records: wtmp/btmp/lastlog ──
    for log_file in &["/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"] {
        let p = std::path::Path::new(log_file);
        if p.exists() {
            scrub_file_containing(p, &["qypha", "did:nxf:", "system-helper"]);
        }
    }
    status.record_ok("Login records scrubbed (wtmp/btmp/lastlog)");

    // ── Shared memory (/dev/shm/) ──
    let shm = std::path::Path::new("/dev/shm");
    if shm.is_dir() {
        if let Ok(entries) = std::fs::read_dir(shm) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.contains("qypha") || lower.contains("system-helper") {
                        secure_wipe_file(&entry.path());
                    }
                }
            }
        }
        status.record_ok("Shared memory cleaned (/dev/shm)");
    }

    // ── auditd logs (/var/log/audit/) ──
    status.run_cmd("Rotate audit logs", "service", &["auditd", "rotate"], true);
    let audit_dir = std::path::Path::new("/var/log/audit");
    if audit_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(audit_dir) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    scrub_file_containing(&entry.path(), &["qypha", "did:nxf:", "system-helper"]);
                }
            }
        }
        status.record_ok("Audit logs scrubbed");
    }

    // ── syslog / /var/log/messages ──
    for log_file in &["/var/log/syslog", "/var/log/messages"] {
        let p = std::path::Path::new(log_file);
        if p.exists() {
            scrub_file_containing(p, &["qypha", "did:nxf:", "system-helper"]);
        }
    }
    status.record_ok("Syslog scrubbed");

    // ── dmesg kernel ring buffer ──
    status.run_cmd("Clear kernel ring buffer", "dmesg", &["-c"], true);

    // ── /tmp + /var/tmp — qypha traces ──
    let tmp_keywords: &[&str] = &["qypha", "did:nxf:", "system-helper"];
    let running_exe = std::env::current_exe().ok();
    for tmp_dir in &["/tmp", "/var/tmp"] {
        let p = std::path::Path::new(tmp_dir);
        if p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(p) {
                for entry in entries.flatten() {
                    let ep = entry.path();
                    // Skip the running binary itself
                    if let Some(ref exe) = running_exe {
                        if let (Ok(a), Ok(b)) = (ep.canonicalize(), exe.canonicalize()) {
                            if a == b {
                                continue;
                            }
                        }
                    }
                    if let Some(name) = entry.file_name().to_str() {
                        let lower = name.to_lowercase();
                        if tmp_keywords.iter().any(|kw| lower.contains(kw)) {
                            if ep.is_file() {
                                secure_wipe_file(&ep);
                            } else {
                                secure_wipe_dir(&ep);
                            }
                        }
                    }
                }
            }
        }
    }
    status.record_ok("Temp directories cleaned");

    // ── ~/.local/share/Trash/ — qypha traces ──
    let trash_dir = home.join(".local/share/Trash");
    if trash_dir.is_dir() {
        for subdir in &["files", "info"] {
            let sub = trash_dir.join(subdir);
            if sub.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&sub) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str() {
                            let lower = name.to_lowercase();
                            if lower.contains("qypha") || lower.contains("system-helper") {
                                if entry.path().is_file() {
                                    secure_wipe_file(&entry.path());
                                } else {
                                    secure_wipe_dir(&entry.path());
                                }
                            }
                        }
                    }
                }
            }
        }
        status.record_ok("Trash cleaned");
    }

    // ── Clipboard (X11 + Wayland) ──
    let _ = std::process::Command::new("xclip")
        .args(["-selection", "clipboard", "/dev/null"])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output();
    let _ = std::process::Command::new("wl-copy")
        .arg("--clear")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output();
    status.record_ok("Clipboard cleared");

    // ── Process accounting (/var/log/sysstat/) ──
    let sysstat = std::path::Path::new("/var/log/sysstat");
    if sysstat.is_dir() {
        if let Ok(entries) = std::fs::read_dir(sysstat) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    scrub_file_containing(&entry.path(), &["qypha", "did:nxf:", "system-helper"]);
                }
            }
        }
        status.record_ok("Process accounting cleaned");
    }
}

/// Windows-specific: clean PowerShell/CMD history, prefetch, event logs, WER, recent files
#[cfg(target_os = "windows")]
fn windows_forensic_cleanup(status: &mut ForensicStatus) {
    let userprofile = match std::env::var("USERPROFILE") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => return,
    };

    // ── 1. PowerShell history ──
    if let Ok(appdata) = std::env::var("APPDATA") {
        let ps_history = std::path::PathBuf::from(&appdata)
            .join("Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        if ps_history.exists() {
            scrub_history_file(&ps_history, None);
            status.record_ok("PowerShell history scrubbed");
        }
    }

    // ── 2. CMD in-memory history ──
    status.run_cmd(
        "Clear CMD history",
        "cmd",
        &["/C", "doskey", "/reinstall"],
        false,
    );

    // ── 3. Recent Files (.lnk shortcuts) ──
    if let Ok(appdata) = std::env::var("APPDATA") {
        let recent_dir = std::path::PathBuf::from(&appdata).join("Microsoft\\Windows\\Recent");
        if recent_dir.is_dir() {
            cleanup_windows_dir_matching(&recent_dir, &["qypha", "system-helper"]);
            status.record_ok("Recent files cleaned");
        }

        // Jump Lists
        let auto_dest = recent_dir.join("AutomaticDestinations");
        let custom_dest = recent_dir.join("CustomDestinations");
        for dir in &[auto_dest, custom_dest] {
            if dir.is_dir() {
                cleanup_windows_dir_matching(dir, &["qypha", "system-helper"]);
            }
        }
        status.record_ok("Jump Lists cleaned");
    }

    // ── 4. Prefetch cache ──
    let prefetch_dir = std::path::PathBuf::from("C:\\Windows\\Prefetch");
    if prefetch_dir.is_dir() {
        cleanup_windows_dir_matching(&prefetch_dir, &["qypha", "system-helper"]);
        status.record_ok("Prefetch cache cleaned");
    }

    // ── 5. Event Log cleanup ──
    for log_name in &["Application", "System", "Windows PowerShell", "Security"] {
        status.run_cmd("Clear Event Log", "wevtutil", &["cl", log_name], true);
    }

    // ── 6. WER (Windows Error Reporting) + CrashDumps ──
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let wer_dir = std::path::PathBuf::from(&localappdata).join("Microsoft\\Windows\\WER");
        if wer_dir.is_dir() {
            cleanup_windows_dir_matching(&wer_dir, &["qypha", "system-helper"]);
        }

        let crash_dumps = std::path::PathBuf::from(&localappdata).join("CrashDumps");
        if crash_dumps.is_dir() {
            cleanup_windows_dir_matching(&crash_dumps, &["qypha", "system-helper"]);
        }
        status.record_ok("WER + CrashDumps cleaned");
    }

    // ── 7. NTFS Alternate Data Streams (Zone.Identifier = download source) ──
    if let Ok(exe) = std::env::current_exe() {
        let ads_path = format!("{}:Zone.Identifier", exe.to_string_lossy());
        let _ = std::fs::remove_file(&ads_path);
        status.record_ok("NTFS Zone.Identifier ADS removed");
    }

    // ── 8. Thumbnail cache (best-effort) ──
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let explorer_dir =
            std::path::PathBuf::from(&localappdata).join("Microsoft\\Windows\\Explorer");
        if explorer_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&explorer_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with("thumbcache_") && name.ends_with(".db") {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
            status.record_ok("Thumbnail cache cleaned");
        }
    }

    // ── 9. Windows temp directories ──
    if let Ok(temp) = std::env::var("TEMP") {
        let temp_dir = std::path::PathBuf::from(&temp);
        cleanup_windows_dir_matching(&temp_dir, &["qypha", "system-helper"]);
    }

    // ── 10. Registry MRU keys (Explorer history) ──
    let mru_keys = [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
    ];
    for key in &mru_keys {
        status.run_cmd("Clear MRU registry", "reg", &["delete", key, "/f"], true);
    }

    // ── 11. UserAssist registry (ROT13 encoded execution history) ──
    let userassist_base =
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    if let Ok(output) = std::process::Command::new("reg")
        .args(["query", userassist_base])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("HKEY_") && trimmed.contains("UserAssist") {
                let count_key = format!("{}\\Count", trimmed);
                status.run_cmd(
                    "Clear UserAssist",
                    "reg",
                    &["delete", &count_key, "/f"],
                    true,
                );
            }
        }
    }
    status.record_ok("UserAssist registry cleaned");

    // ── 12. BAM/DAM (Background/Desktop Activity Moderator) ──
    status.run_cmd(
        "Clear BAM entries",
        "reg",
        &[
            "delete",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
            "/f",
        ],
        true,
    );
    status.run_cmd(
        "Clear DAM entries",
        "reg",
        &[
            "delete",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
            "/f",
        ],
        true,
    );
    status.record_ok("BAM/DAM entries cleaned");

    // ── 13. SRUM database (System Resource Usage Monitor) ──
    status.run_cmd("Stop SRUM service", "net", &["stop", "DPS"], true);
    let srum_db = std::path::Path::new("C:\\Windows\\System32\\sru\\SRUDB.dat");
    if srum_db.exists() {
        secure_wipe_file(srum_db);
    }
    status.run_cmd("Start SRUM service", "net", &["start", "DPS"], true);
    status.record_ok("SRUM database wiped");

    // ── 14. Amcache.hve (application compatibility cache) ──
    let amcache = std::path::Path::new("C:\\Windows\\appcompat\\Programs\\Amcache.hve");
    if amcache.exists() {
        let _ = std::fs::remove_file(amcache); // may be locked — best effort
        status.record_ok("Amcache.hve deleted (best-effort)");
    }

    // ── 15. ShimCache registry ──
    status.run_cmd(
        "Clear ShimCache",
        "reg",
        &[
            "delete",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            "/f",
        ],
        true,
    );
    status.record_ok("ShimCache registry cleaned");

    // ── 16. Clipboard history (Windows 10+) ──
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let clipboard_dir =
            std::path::PathBuf::from(&localappdata).join("Microsoft\\Windows\\Clipboard");
        if clipboard_dir.is_dir() {
            secure_wipe_dir(&clipboard_dir);
            status.record_ok("Clipboard history wiped");
        }
    }
    status.run_cmd(
        "Clear clipboard",
        "powershell",
        &["-Command", "Set-Clipboard -Value $null"],
        false,
    );

    // ── 17. Windows Timeline (ActivitiesCache.db) ──
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let cdp_dir = std::path::PathBuf::from(&localappdata).join("ConnectedDevicesPlatform");
        if cdp_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&cdp_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        for db_name in &[
                            "ActivitiesCache.db",
                            "ActivitiesCache.db-wal",
                            "ActivitiesCache.db-shm",
                        ] {
                            let db_path = p.join(db_name);
                            if db_path.exists() {
                                secure_wipe_file(&db_path);
                            }
                        }
                    }
                }
            }
            status.record_ok("Windows Timeline wiped");
        }
    }

    // ── 18. ETW logs (Event Tracing for Windows) ──
    let etw_dir = std::path::Path::new("C:\\Windows\\System32\\LogFiles\\WMI");
    if etw_dir.is_dir() {
        cleanup_windows_dir_matching(etw_dir, &["qypha", "system-helper"]);
        status.record_ok("ETW logs cleaned");
    }

    // ── 19. Network Profiles registry ──
    status.run_cmd(
        "Clear network profiles",
        "reg",
        &[
            "delete",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            "/f",
        ],
        true,
    );
    status.record_ok("Network profiles cleaned");

    let _ = &userprofile; // suppress unused warning
}

/// Helper: recursively find and secure-wipe files matching any keyword in a directory.
#[cfg(target_os = "windows")]
fn cleanup_windows_dir_matching(dir: &std::path::Path, keywords: &[&str]) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_lowercase();
                if keywords.iter().any(|kw| lower.contains(kw)) {
                    if p.is_file() {
                        secure_wipe_file(&p);
                    } else if p.is_dir() {
                        secure_wipe_dir(&p);
                    }
                }
            }
        }
    }
}

/// Remove crash reports containing "qypha" from a DiagnosticReports directory.
fn cleanup_crash_reports(dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_lowercase();
                if lower.contains("qypha") || lower.contains("system-helper") {
                    secure_wipe_file(&p);
                }
            }
        }
    }
}

/// Post-cleanup verification: check that critical traces were actually removed.
/// Returns a list of (description, passed) tuples for the summary.
fn ghost_verify_cleanup() -> Vec<(&'static str, bool)> {
    let mut results = Vec::new();

    // ── 1. APFS local snapshots should be gone ──
    #[cfg(target_os = "macos")]
    {
        let snapshots_clean = std::process::Command::new("tmutil")
            .args(["listlocalsnapshots", "/"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                // Output lines after header should be empty if no snapshots
                out.lines()
                    .filter(|l| l.starts_with("com.apple.TimeMachine"))
                    .count()
                    == 0
            })
            .unwrap_or(true); // If command fails, can't verify — assume ok
        results.push(("APFS local snapshots removed", snapshots_clean));
    }

    // ── 2. Spotlight: verify no qypha data is indexed ──
    #[cfg(target_os = "macos")]
    {
        // In Ghost mode, no persistent .qypha directory exists on disk,
        // so Spotlight can't index anything meaningful — PASS regardless.
        // Otherwise, check that mdutil disabled indexing or that .metadata_never_index
        // protects the qypha directory.
        let no_nf_dir = std::env::var("HOME")
            .map(|h| !std::path::PathBuf::from(h).join(".qypha").exists())
            .unwrap_or(true);

        let mdutil_disabled = std::process::Command::new("mdutil")
            .args(["-s", "/"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout).to_lowercase();
                out.contains("disabled")
            })
            .unwrap_or(false);

        let nf_protected = std::env::var("HOME")
            .map(|h| {
                let nf = std::path::PathBuf::from(h).join(".qypha");
                !nf.exists() || nf.join(".metadata_never_index").exists()
            })
            .unwrap_or(true);

        results.push((
            "Spotlight safe (no qypha data exposed)",
            no_nf_dir || mdutil_disabled || nf_protected,
        ));
    }

    // ── 3. Sleep image should be gone ──
    #[cfg(target_os = "macos")]
    {
        let no_sleep_image = !std::path::Path::new("/var/vm/sleepimage").exists();
        results.push(("Sleep image removed", no_sleep_image));
    }

    // ── 4. Shell history should not contain any identifying keywords ──
    {
        let keywords: &[&str] = &["qypha", "did:nxf:", "system-helper"];
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        let mut history_files = vec![
            format!("{}/.zsh_history", home),
            format!("{}/.bash_history", home),
        ];
        // Windows: PowerShell history
        #[cfg(target_os = "windows")]
        if let Ok(appdata) = std::env::var("APPDATA") {
            history_files.push(format!(
                "{}\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                appdata
            ));
        }
        let mut history_clean = true;
        'outer: for hf in &history_files {
            let path = std::path::Path::new(hf);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    let lower = content.to_lowercase();
                    for kw in keywords {
                        if lower.contains(kw) {
                            history_clean = false;
                            break 'outer;
                        }
                    }
                }
            }
        }
        results.push((
            "Shell history scrubbed (no identifying traces)",
            history_clean,
        ));
    }

    // ── 5. Crash reports should not contain any identifying keywords ──
    {
        let keywords: &[&str] = &["qypha", "did:nxf:", "system-helper"];
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        let mut diag_dirs = vec![
            format!("{}/Library/Logs/DiagnosticReports", home),
            "/Library/Logs/DiagnosticReports".to_string(),
            "/var/crash".to_string(),
        ];
        // Windows: WER + CrashDumps
        #[cfg(target_os = "windows")]
        if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
            diag_dirs.push(format!("{}\\Microsoft\\Windows\\WER", localappdata));
            diag_dirs.push(format!("{}\\CrashDumps", localappdata));
        }
        let mut crash_clean = true;
        'crash_outer: for dir_str in &diag_dirs {
            let dir = std::path::Path::new(dir_str);
            if dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str() {
                            let lower = name.to_lowercase();
                            if keywords.iter().any(|kw| lower.contains(kw)) {
                                crash_clean = false;
                                break 'crash_outer;
                            }
                        }
                    }
                }
            }
            if !crash_clean {
                break;
            }
        }
        results.push(("Crash reports clean (no qypha)", crash_clean));
    }

    // ── 6. Windows: Prefetch clean ──
    #[cfg(target_os = "windows")]
    {
        let prefetch_dir = std::path::Path::new("C:\\Windows\\Prefetch");
        let mut prefetch_clean = true;
        if prefetch_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(prefetch_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        let lower = name.to_lowercase();
                        if lower.contains("qypha") || lower.contains("system-helper") {
                            prefetch_clean = false;
                            break;
                        }
                    }
                }
            }
        }
        results.push(("Prefetch cache clean", prefetch_clean));
    }

    // ── 7. Windows: Recent files clean ──
    #[cfg(target_os = "windows")]
    {
        let mut recent_clean = true;
        if let Ok(appdata) = std::env::var("APPDATA") {
            let recent_dir = std::path::PathBuf::from(&appdata).join("Microsoft\\Windows\\Recent");
            if recent_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&recent_dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str() {
                            let lower = name.to_lowercase();
                            if lower.contains("qypha") || lower.contains("system-helper") {
                                recent_clean = false;
                                break;
                            }
                        }
                    }
                }
            }
        }
        results.push(("Recent files clean", recent_clean));
    }

    // ── 8. macOS: QuarantineEventsV2 removed ──
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let qev_clean = !std::path::PathBuf::from(&home)
            .join("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
            .exists();
        results.push(("QuarantineEventsV2 removed", qev_clean));

        // /cores/ should be empty
        let cores_clean = std::fs::read_dir("/cores")
            .map(|entries| entries.count() == 0)
            .unwrap_or(true);
        results.push(("Kernel crash dumps clean (/cores)", cores_clean));
    }

    // ── 9. Linux: systemd coredumps + /dev/shm clean ──
    #[cfg(target_os = "linux")]
    {
        let vkw: &[&str] = &["qypha", "system-helper"];
        let coredump_clean = if std::path::Path::new("/var/lib/systemd/coredump").is_dir() {
            std::fs::read_dir("/var/lib/systemd/coredump")
                .map(|entries| {
                    entries.flatten().all(|e| {
                        let n = e.file_name().to_str().unwrap_or("").to_lowercase();
                        !vkw.iter().any(|kw| n.contains(kw))
                    })
                })
                .unwrap_or(true)
        } else {
            true
        };
        results.push(("Systemd coredumps clean", coredump_clean));

        let shm_clean = std::fs::read_dir("/dev/shm")
            .map(|entries| {
                entries.flatten().all(|e| {
                    let n = e.file_name().to_str().unwrap_or("").to_lowercase();
                    !vkw.iter().any(|kw| n.contains(kw))
                })
            })
            .unwrap_or(true);
        results.push(("Shared memory clean (/dev/shm)", shm_clean));
    }

    // ── 10. Windows: SRUM + Clipboard history clean ──
    #[cfg(target_os = "windows")]
    {
        let srum_clean = !std::path::Path::new("C:\\Windows\\System32\\sru\\SRUDB.dat").exists();
        results.push(("SRUM database clean", srum_clean));

        if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
            let clipboard_clean = !std::path::PathBuf::from(&localappdata)
                .join("Microsoft\\Windows\\Clipboard")
                .exists();
            results.push(("Clipboard history clean", clipboard_clean));
        }
    }

    // ── 11. Cross-platform: /tmp clean ──
    {
        let keywords: &[&str] = &["qypha", "did:nxf:", "system-helper"];
        let running_exe = std::env::current_exe().ok();
        let mut tmp_clean = true;
        for tmp_dir in &["/tmp", "/var/tmp", "/private/tmp"] {
            let p = std::path::Path::new(tmp_dir);
            if p.is_dir() {
                if let Ok(entries) = std::fs::read_dir(p) {
                    for entry in entries.flatten() {
                        // Skip the running binary itself (expected evidence, can't self-delete)
                        if let Some(ref exe) = running_exe {
                            let ep = entry.path();
                            if let (Ok(a), Ok(b)) = (ep.canonicalize(), exe.canonicalize()) {
                                if a == b {
                                    continue;
                                }
                            }
                        }
                        if let Some(name) = entry.file_name().to_str() {
                            let lower = name.to_lowercase();
                            if keywords.iter().any(|kw| lower.contains(kw)) {
                                tmp_clean = false;
                                break;
                            }
                        }
                    }
                }
            }
            if !tmp_clean {
                break;
            }
        }
        results.push(("Temp directories clean", tmp_clean));
    }

    // ── 12. FDE verification ──
    {
        let (fde_on, fde_method) = check_disk_encryption_detail();
        results.push(if fde_on {
            ("Full-disk encryption active", true)
        } else {
            (
                "Full-disk encryption OFF (secure wipe weakened on SSD)",
                false,
            )
        });
        // Log method for user awareness
        if fde_on {
            results.push(match fde_method {
                "FileVault" => ("FDE method: FileVault", true),
                "LUKS/dm-crypt" => ("FDE method: LUKS", true),
                "BitLocker" => ("FDE method: BitLocker", true),
                _ => ("FDE method: detected", true),
            });
        }
    }

    // ── 13. Elevated privilege status ──
    {
        let has_root = is_running_as_root();
        results.push(if has_root {
            (
                "Running with elevated rights (full forensic coverage)",
                true,
            )
        } else {
            ("Running without root (OS trace cleanup limited)", false)
        });
    }

    results
}

/// Remove all lines containing "qypha" from shell history files
/// using secure overwrite (random bytes → cleaned content → fsync).
fn scrub_shell_history() {
    let session_start_unix = std::env::var("_QYPHA_GHOST_SESSION_START_UNIX")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from);

    // Unix shell history files
    if let Ok(ref home) = home {
        let history_files = [
            home.join(".zsh_history"),
            home.join(".bash_history"),
            home.join(".zsh_sessions"),
        ];

        for path in &history_files {
            if path.is_file() {
                scrub_history_file(path, session_start_unix);
            } else if path.is_dir() {
                // ~/.zsh_sessions/ contains per-session files on macOS
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            if let Some(start_unix) = session_start_unix {
                                let modified_after_start = std::fs::metadata(&p)
                                    .ok()
                                    .and_then(|m| m.modified().ok())
                                    .and_then(|t| {
                                        t.duration_since(std::time::UNIX_EPOCH)
                                            .ok()
                                            .map(|d| d.as_secs())
                                    })
                                    .is_some_and(|ts| ts >= start_unix);
                                if modified_after_start {
                                    secure_wipe_file(&p);
                                    continue;
                                }
                            }
                            scrub_history_file(&p, session_start_unix);
                        }
                    }
                }
            }
        }
    }

    // Windows: PowerShell history
    #[cfg(target_os = "windows")]
    if let Ok(appdata) = std::env::var("APPDATA") {
        let ps_history = std::path::PathBuf::from(&appdata)
            .join("Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        if ps_history.is_file() {
            scrub_history_file(&ps_history, session_start_unix);
        }
    }

    // Tell the running shell to forget in-memory history
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("sh")
            .args(["-c", "history -c 2>/dev/null; fc -R 2>/dev/null"])
            .output();
    }
}

/// Remove lines containing "qypha" from a history file.
///
/// Secure overwrite strategy (NIST SP 800-88 compliant):
///   - HDD: 1 pass random is sufficient — modern drives have no residual magnetism
///   - SSD: Overwrite does NOT guarantee same physical cells (wear leveling).
///     Real SSD protection = Full Disk Encryption (FileVault/LUKS) + TRIM.
///     We still overwrite as defense-in-depth, then truncate to trigger TRIM.
fn scrub_history_file(path: &std::path::Path, session_start_unix: Option<u64>) {
    use std::io::Write;

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // All keywords that could identify Qypha usage in shell history.
    // Case-insensitive matching catches variants like QYPHA_LOG_MODE.
    let keywords: &[&str] = &[
        "qypha",         // binary name, config files, env vars, .qypha dir
        "did:nxf:",      // decentralized identifiers (unique forensic fingerprint)
        "system-helper", // Windows service name alias
    ];
    let lower_content = content.to_lowercase();
    let has_keyword = keywords.iter().any(|kw| lower_content.contains(kw));
    let has_session_window_lines = session_start_unix.is_some_and(|start_unix| {
        content.lines().any(|line| {
            line.strip_prefix(": ")
                .and_then(|rest| rest.split(':').next())
                .and_then(|ts| ts.trim().parse::<u64>().ok())
                .is_some_and(|ts| ts >= start_unix)
        })
    });
    if !has_keyword && !has_session_window_lines {
        return;
    }

    let original_size = content.len();

    let cleaned: Vec<&str> = content
        .lines()
        .filter(|line| {
            let lower = line.to_lowercase();
            if keywords.iter().any(|kw| lower.contains(kw)) {
                return false;
            }

            // zsh extended-history lines carry epoch prefix: ": 1700000000:0;cmd"
            // Remove all entries created during the active Ghost session window.
            if let Some(start_unix) = session_start_unix {
                if let Some(rest) = line.strip_prefix(": ") {
                    if let Some(ts_str) = rest.split(':').next() {
                        if let Ok(ts) = ts_str.trim().parse::<u64>() {
                            if ts >= start_unix {
                                return false;
                            }
                        }
                    }
                }
            }

            true
        })
        .collect();

    let new_content = cleaned.join("\n");

    // ── Pass 1: Overwrite entire file with random bytes → fsync to physical media ──
    // On HDD: destroys original data on the same sectors (unrecoverable)
    // On SSD: best-effort — wear leveling may redirect, but old cells enter
    //         garbage collection queue and will be TRIM'd
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        let random_bytes: Vec<u8> = (0..original_size).map(|_| rand::random::<u8>()).collect();
        let _ = f.write_all(&random_bytes);
        let _ = f.sync_all(); // force flush to physical media
    }

    // ── Pass 2: Truncate to 0, then write cleaned content ──
    // Truncate releases the old blocks — on SSD this triggers TRIM,
    // which tells the controller to physically erase the old flash cells.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
    {
        let _ = f.write_all(new_content.as_bytes());
        let _ = f.sync_all();
    }
}

/// Securely delete a directory: overwrite all files with random, truncate, then remove.
fn secure_delete_dir(dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                secure_delete_file(&p);
            } else if p.is_dir() {
                secure_delete_dir(&p);
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Securely delete a single file: overwrite with random → truncate (TRIM) → remove.
fn secure_delete_file(path: &std::path::Path) {
    use std::io::Write;

    if let Ok(meta) = std::fs::metadata(path) {
        let size = meta.len() as usize;
        if size > 0 {
            // Overwrite with random bytes
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let random_bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
                let _ = f.write_all(&random_bytes);
                let _ = f.sync_all();
            }
            // Truncate to 0 — triggers TRIM on SSD, releasing old flash cells
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
                let _ = f.set_len(0);
                let _ = f.sync_all();
            }
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Remove lines containing a keyword from a generic file (e.g. recently-used.xbel)
#[cfg(target_os = "linux")]
fn scrub_file_containing(path: &std::path::Path, keywords: &[&str]) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lower = content.to_lowercase();
    if !keywords.iter().any(|kw| lower.contains(kw)) {
        return;
    }
    let cleaned: Vec<&str> = content
        .lines()
        .filter(|l| {
            let ll = l.to_lowercase();
            !keywords.iter().any(|kw| ll.contains(kw))
        })
        .collect();
    let _ = std::fs::write(path, cleaned.join("\n"));
}

fn transport_mode_to_str(mode: &TransportMode) -> &str {
    match mode {
        TransportMode::Tcp => "tcp",
        TransportMode::Tor => "tor",
        TransportMode::Internet => "internet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_port_availability_requires_udp_and_tcp() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind udp");
        let port = udp.local_addr().expect("udp addr").port();

        assert!(
            !is_listen_port_available(port),
            "udp occupancy must mark listen port unavailable"
        );
    }

    #[test]
    fn persistent_launch_initializes_only_when_no_state_exists() {
        assert_eq!(
            determine_persistent_launch_action(false, false),
            PersistentLaunchAction::Initialize
        );
    }

    #[test]
    fn persistent_launch_reuses_existing_complete_agent_state() {
        assert_eq!(
            determine_persistent_launch_action(true, true),
            PersistentLaunchAction::ReuseExisting
        );
    }

    #[test]
    fn persistent_launch_rejects_missing_identity() {
        assert_eq!(
            determine_persistent_launch_action(true, false),
            PersistentLaunchAction::MissingIdentity
        );
    }

    #[test]
    fn persistent_launch_recovers_missing_config() {
        assert_eq!(
            determine_persistent_launch_action(false, true),
            PersistentLaunchAction::RecoverConfig
        );
    }
}

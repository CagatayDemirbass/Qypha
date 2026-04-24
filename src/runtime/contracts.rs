use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAccessMode {
    Restricted,
    FullAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Ollama,
    OpenAi,
    Anthropic,
    Gemini,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSessionMode {
    Ephemeral,
    Persistent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsExecutionKind {
    TypedOperation,
    ShellFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Accepted,
    Running,
    Blocked,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeProgressEvent {
    pub status: RuntimeStatus,
    pub message: String,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCatalogEntry {
    pub provider: ProviderKind,
    pub model_id: String,
    pub label: String,
    pub local: bool,
    #[serde(default)]
    pub supports_tools: bool,
    #[serde(default)]
    pub supports_vision: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderGenerateRequest {
    pub provider: ProviderKind,
    pub model_id: String,
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub messages: Vec<ProviderMessage>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderGenerateResponse {
    pub model_id: String,
    pub output_text: String,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSearchRequest {
    pub query: String,
    #[serde(default)]
    pub recency_required: bool,
    #[serde(default)]
    pub technical_only: bool,
    #[serde(default)]
    pub max_results: usize,
    #[serde(default)]
    pub scope: Option<ResearchSourceScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResearchDisposition {
    AnswerDirectly,
    SearchWeb,
    InspectSpecificSources,
    UseBrowser,
    ReadDocument,
    InspectRepo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchPlanRequest {
    pub query: String,
    #[serde(default)]
    pub current_answer_draft: Option<String>,
    #[serde(default)]
    pub local_context_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchPlanResponse {
    pub disposition: ResearchDisposition,
    pub rationale: String,
    #[serde(default)]
    pub planned_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSource {
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub snippet: Option<String>,
    #[serde(default)]
    pub source_kind: Option<String>,
    #[serde(default)]
    pub score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceClassification {
    Primary,
    Secondary,
    Summary,
    News,
    Repo,
    Paper,
    OfficialDoc,
    Web,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSourceScope {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub prioritized_domains: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_open_web: bool,
    #[serde(default)]
    pub allow_connected_sources: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchActionLogEntry {
    pub action: String,
    pub at_ms: i64,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsultedSourceRecord {
    pub source: ResearchSource,
    pub classification: SourceClassification,
    pub extraction_mode: String,
    pub accessed_at_ms: i64,
    pub content_length_chars: usize,
    #[serde(default)]
    pub page_ranges: Vec<String>,
    #[serde(default)]
    pub headings: Vec<String>,
    #[serde(default)]
    pub find_queries: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectedResearchSource {
    pub source: ResearchSource,
    pub extracted_text: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub disagreement_flags: Vec<String>,
    #[serde(default)]
    pub consulted_source: Option<ConsultedSourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSearchResponse {
    pub query: String,
    pub sources: Vec<ResearchSource>,
    #[serde(default)]
    pub action_log: Vec<ResearchActionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchInspectRequest {
    pub query: String,
    pub sources: Vec<ResearchSource>,
    #[serde(default)]
    pub max_sources: usize,
    #[serde(default)]
    pub scope: Option<ResearchSourceScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchInspectResponse {
    pub query: String,
    pub inspected_sources: Vec<InspectedResearchSource>,
    #[serde(default)]
    pub consulted_sources: Vec<ConsultedSourceRecord>,
    #[serde(default)]
    pub action_log: Vec<ResearchActionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchOpenPageRequest {
    pub session_id: String,
    pub source: ResearchSource,
    #[serde(default)]
    pub scope: Option<ResearchSourceScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchOpenPageResponse {
    pub snapshot: BrowserSnapshot,
    pub consulted_source: ConsultedSourceRecord,
    #[serde(default)]
    pub action_log: Vec<ResearchActionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchFindInPageRequest {
    pub session_id: String,
    pub query: String,
    #[serde(default)]
    pub source: Option<ResearchSource>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub max_matches: usize,
    #[serde(default)]
    pub scope: Option<ResearchSourceScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchPageMatch {
    pub line_number: usize,
    #[serde(default)]
    pub heading: Option<String>,
    pub excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchFindInPageResponse {
    pub session_id: String,
    pub url: String,
    pub query: String,
    pub matches: Vec<ResearchPageMatch>,
    #[serde(default)]
    pub consulted_source: Option<ConsultedSourceRecord>,
    #[serde(default)]
    pub action_log: Vec<ResearchActionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSynthesisRequest {
    pub query: String,
    #[serde(default)]
    pub sources: Vec<ResearchSource>,
    #[serde(default)]
    pub inspected_sources: Vec<InspectedResearchSource>,
    #[serde(default)]
    pub consulted_sources: Vec<ConsultedSourceRecord>,
    #[serde(default)]
    pub desired_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchSynthesisResponse {
    pub answer: String,
    #[serde(default)]
    pub uncertainty: Option<String>,
    #[serde(default)]
    pub citations: Vec<String>,
    #[serde(default)]
    pub sources_used: Vec<ConsultedSourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSessionSpec {
    pub session_id: String,
    pub mode: BrowserSessionMode,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserOpenRequest {
    pub session_id: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInteractRequest {
    pub session_id: String,
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownloadRequest {
    pub session_id: String,
    pub url: String,
    #[serde(default)]
    pub destination: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSnapshot {
    pub session_id: String,
    pub url: String,
    pub markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownloadResult {
    pub session_id: String,
    pub url: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentReadRequest {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSection {
    pub heading: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentReadResponse {
    pub path: PathBuf,
    pub sections: Vec<DocumentSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRenderRequest {
    pub actor_id: String,
    pub session_id: String,
    pub artifact_kind: String,
    #[serde(default)]
    pub title: Option<String>,
    pub body: String,
    pub output_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRenderResponse {
    pub artifact_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactValidateRequest {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactValidateResponse {
    pub ok: bool,
    #[serde(default)]
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPublishRequest {
    pub actor_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub destination: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPublishResponse {
    pub artifact_id: String,
    pub stored_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWriteRequest {
    pub actor_id: String,
    pub scope: String,
    pub content: String,
    #[serde(default)]
    pub source_links: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub memory_id: String,
    pub actor_id: String,
    pub scope: String,
    pub content: String,
    #[serde(default)]
    pub source_links: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetRequest {
    pub actor_id: String,
    pub memory_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySearchRequest {
    pub actor_id: String,
    pub query: String,
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCompressRequest {
    pub actor_id: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStalenessCheckRequest {
    pub actor_id: String,
    pub memory_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStalenessCheckResult {
    pub memory_id: String,
    pub stale: bool,
    #[serde(default)]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsRunCommand {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OsOperation {
    ReadText {
        path: PathBuf,
    },
    WriteText {
        path: PathBuf,
        content: String,
        create_parents: bool,
    },
    ListDir {
        path: PathBuf,
    },
    SearchFiles {
        root: PathBuf,
        pattern: String,
    },
    MakeDir {
        path: PathBuf,
    },
    MovePath {
        from: PathBuf,
        to: PathBuf,
    },
    CopyPath {
        from: PathBuf,
        to: PathBuf,
    },
    DeletePath {
        path: PathBuf,
        recursive: bool,
    },
    Archive {
        source: PathBuf,
        destination: PathBuf,
        format: String,
    },
    Extract {
        archive: PathBuf,
        destination: PathBuf,
    },
    OpenPath {
        path: PathBuf,
    },
    LaunchApp {
        command: OsRunCommand,
    },
    ListProcesses,
    ClipboardRead,
    ClipboardWrite {
        text: String,
    },
    Notify {
        title: String,
        body: String,
    },
    RunCommand {
        command: OsRunCommand,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsOperationRequest {
    pub actor_id: String,
    pub access_mode: RuntimeAccessMode,
    pub execution_kind: OsExecutionKind,
    pub operation: OsOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsOperationResult {
    pub status: RuntimeStatus,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoOverviewRequest {
    pub root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoOverviewResponse {
    pub root: PathBuf,
    #[serde(default)]
    pub vcs: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    pub dirty: bool,
    #[serde(default)]
    pub changed_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoTreeRequest {
    pub root: PathBuf,
    #[serde(default)]
    pub depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoTreeEntry {
    pub path: PathBuf,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoTreeResponse {
    pub root: PathBuf,
    pub entries: Vec<RepoTreeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSearchRequest {
    pub root: PathBuf,
    pub pattern: String,
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSearchMatch {
    pub path: PathBuf,
    pub line_number: usize,
    pub line_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSearchResponse {
    pub root: PathBuf,
    pub matches: Vec<RepoSearchMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReadFileRequest {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReadFileResponse {
    pub path: PathBuf,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoGitLogRequest {
    pub root: PathBuf,
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoGitCommitEntry {
    pub commit_id: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoGitLogResponse {
    pub root: PathBuf,
    pub commits: Vec<RepoGitCommitEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRemoteInspectRequest {
    pub url: String,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRemoteInspectResponse {
    pub url: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub candidate_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub plugin_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub server_name: String,
    #[serde(default)]
    pub plugin_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilityInfo {
    pub capability_id: String,
    pub kind: String,
    #[serde(default)]
    pub plugin_id: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMcpInvokeRequest {
    pub capability_id: String,
    #[serde(default)]
    pub args_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMcpInvokeResponse {
    pub capability_id: String,
    pub output_json: String,
}

#[async_trait]
pub trait ProviderRuntime: Send + Sync {
    async fn healthcheck(&self) -> Result<()>;
    async fn list_models(&self, provider: ProviderKind) -> Result<Vec<ProviderCatalogEntry>>;
    async fn generate(&self, request: ProviderGenerateRequest) -> Result<ProviderGenerateResponse>;
}

#[async_trait]
pub trait ResearchRuntime: Send + Sync {
    async fn plan(&self, request: ResearchPlanRequest) -> Result<ResearchPlanResponse>;
    async fn search(&self, request: ResearchSearchRequest) -> Result<ResearchSearchResponse>;
    async fn inspect(&self, request: ResearchInspectRequest) -> Result<ResearchInspectResponse>;
    async fn open_page(&self, request: ResearchOpenPageRequest)
        -> Result<ResearchOpenPageResponse>;
    async fn find_in_page(
        &self,
        request: ResearchFindInPageRequest,
    ) -> Result<ResearchFindInPageResponse>;
    async fn synthesize(
        &self,
        request: ResearchSynthesisRequest,
    ) -> Result<ResearchSynthesisResponse>;
}

#[async_trait]
pub trait BrowserRuntime: Send + Sync {
    async fn start_session(&self, spec: BrowserSessionSpec) -> Result<()>;
    async fn open(&self, request: BrowserOpenRequest) -> Result<BrowserSnapshot>;
    async fn snapshot(&self, session_id: &str) -> Result<BrowserSnapshot>;
    async fn interact(&self, request: BrowserInteractRequest) -> Result<BrowserSnapshot>;
    async fn download(&self, request: BrowserDownloadRequest) -> Result<BrowserDownloadResult>;
}

#[async_trait]
pub trait DocumentRuntime: Send + Sync {
    async fn read(&self, request: DocumentReadRequest) -> Result<DocumentReadResponse>;
}

#[async_trait]
pub trait ArtifactRuntime: Send + Sync {
    async fn render(&self, request: ArtifactRenderRequest) -> Result<ArtifactRenderResponse>;
    async fn validate(&self, request: ArtifactValidateRequest) -> Result<ArtifactValidateResponse>;
    async fn publish(&self, request: ArtifactPublishRequest) -> Result<ArtifactPublishResponse>;
}

#[async_trait]
pub trait MemoryRuntime: Send + Sync {
    async fn get(&self, request: MemoryGetRequest) -> Result<Option<MemoryEntry>>;
    async fn write(&self, request: MemoryWriteRequest) -> Result<MemoryEntry>;
    async fn search(&self, request: MemorySearchRequest) -> Result<Vec<MemoryEntry>>;
    async fn compress(&self, request: MemoryCompressRequest) -> Result<Option<MemoryEntry>>;
    async fn staleness_check(
        &self,
        request: MemoryStalenessCheckRequest,
    ) -> Result<MemoryStalenessCheckResult>;
}

#[async_trait]
pub trait OsRuntime: Send + Sync {
    async fn execute(&self, request: OsOperationRequest) -> Result<OsOperationResult>;
}

#[async_trait]
pub trait RepoRuntime: Send + Sync {
    async fn overview(&self, request: RepoOverviewRequest) -> Result<RepoOverviewResponse>;
    async fn tree(&self, request: RepoTreeRequest) -> Result<RepoTreeResponse>;
    async fn grep(&self, request: RepoSearchRequest) -> Result<RepoSearchResponse>;
    async fn read_file(&self, request: RepoReadFileRequest) -> Result<RepoReadFileResponse>;
    async fn git_log(&self, request: RepoGitLogRequest) -> Result<RepoGitLogResponse>;
    async fn remote_inspect(
        &self,
        request: RepoRemoteInspectRequest,
    ) -> Result<RepoRemoteInspectResponse>;
}

#[async_trait]
pub trait PluginMcpRuntime: Send + Sync {
    async fn list_plugins(&self) -> Result<Vec<PluginInfo>>;
    async fn list_servers(&self) -> Result<Vec<McpServerInfo>>;
    async fn resolve_capability(&self, capability_id: &str)
        -> Result<Option<PluginCapabilityInfo>>;
    async fn invoke(&self, request: PluginMcpInvokeRequest) -> Result<PluginMcpInvokeResponse>;
}

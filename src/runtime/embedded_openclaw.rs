use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;

use crate::agent::launch::{
    build_embedded_worker_metadata, normalized_ollama_host, run_embedded_browser_download,
    run_embedded_browser_interact, run_embedded_browser_open, run_embedded_browser_snapshot,
    run_embedded_browser_start_session, run_embedded_document_read, run_embedded_memory_compress,
    run_embedded_memory_get, run_embedded_memory_search, run_embedded_memory_staleness_check,
    run_embedded_memory_write, run_embedded_os_execute, run_embedded_plugin_mcp_invoke,
    run_embedded_plugin_mcp_list_plugins, run_embedded_plugin_mcp_list_servers,
    run_embedded_plugin_mcp_resolve_capability, run_embedded_provider_generate,
    run_embedded_provider_healthcheck, run_embedded_provider_list_models,
    run_embedded_repo_git_log, run_embedded_repo_grep, run_embedded_repo_overview,
    run_embedded_repo_read_file, run_embedded_repo_remote_inspect, run_embedded_repo_tree,
    run_embedded_research_find_in_page, run_embedded_research_inspect,
    run_embedded_research_open_page, run_embedded_research_plan, run_embedded_research_search,
    run_embedded_research_synthesize,
};
use crate::runtime::contracts::{
    BrowserDownloadRequest, BrowserDownloadResult, BrowserInteractRequest, BrowserOpenRequest,
    BrowserRuntime, BrowserSessionSpec, BrowserSnapshot, DocumentReadRequest, DocumentReadResponse,
    DocumentRuntime, McpServerInfo, MemoryCompressRequest, MemoryEntry, MemoryGetRequest,
    MemoryRuntime, MemorySearchRequest, MemoryStalenessCheckRequest, MemoryStalenessCheckResult,
    MemoryWriteRequest, OsOperationRequest, OsOperationResult, OsRuntime, PluginCapabilityInfo,
    PluginInfo, PluginMcpInvokeRequest, PluginMcpInvokeResponse, PluginMcpRuntime,
    ProviderCatalogEntry, ProviderGenerateRequest, ProviderGenerateResponse, ProviderKind,
    ProviderRuntime, RepoGitLogRequest, RepoGitLogResponse, RepoOverviewRequest,
    RepoOverviewResponse, RepoReadFileRequest, RepoReadFileResponse, RepoRemoteInspectRequest,
    RepoRemoteInspectResponse, RepoRuntime, RepoSearchRequest, RepoSearchResponse, RepoTreeRequest,
    RepoTreeResponse, ResearchFindInPageRequest, ResearchFindInPageResponse,
    ResearchInspectRequest, ResearchInspectResponse, ResearchOpenPageRequest,
    ResearchOpenPageResponse, ResearchPlanRequest, ResearchPlanResponse, ResearchRuntime,
    ResearchSearchRequest, ResearchSearchResponse, ResearchSynthesisRequest,
    ResearchSynthesisResponse,
};

fn default_embedded_metadata(agent_name: &str) -> HashMap<String, String> {
    build_embedded_worker_metadata(agent_name, None)
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawProviderRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawProviderRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl ProviderRuntime for EmbeddedOpenClawProviderRuntime {
    async fn healthcheck(&self) -> Result<()> {
        run_embedded_provider_healthcheck(self.request_metadata()).await
    }

    async fn list_models(&self, provider: ProviderKind) -> Result<Vec<ProviderCatalogEntry>> {
        run_embedded_provider_list_models(provider, self.request_metadata()).await
    }

    async fn generate(&self, request: ProviderGenerateRequest) -> Result<ProviderGenerateResponse> {
        run_embedded_provider_generate(request, self.request_metadata()).await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawMemoryRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawMemoryRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl MemoryRuntime for EmbeddedOpenClawMemoryRuntime {
    async fn get(&self, request: MemoryGetRequest) -> Result<Option<MemoryEntry>> {
        run_embedded_memory_get(request, self.request_metadata()).await
    }

    async fn write(&self, request: MemoryWriteRequest) -> Result<MemoryEntry> {
        run_embedded_memory_write(request, self.request_metadata()).await
    }

    async fn search(&self, request: MemorySearchRequest) -> Result<Vec<MemoryEntry>> {
        run_embedded_memory_search(request, self.request_metadata()).await
    }

    async fn compress(&self, request: MemoryCompressRequest) -> Result<Option<MemoryEntry>> {
        run_embedded_memory_compress(request, self.request_metadata()).await
    }

    async fn staleness_check(
        &self,
        request: MemoryStalenessCheckRequest,
    ) -> Result<MemoryStalenessCheckResult> {
        run_embedded_memory_staleness_check(request, self.request_metadata()).await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawRepoRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawRepoRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl RepoRuntime for EmbeddedOpenClawRepoRuntime {
    async fn overview(&self, request: RepoOverviewRequest) -> Result<RepoOverviewResponse> {
        run_embedded_repo_overview(request, self.request_metadata()).await
    }

    async fn tree(&self, request: RepoTreeRequest) -> Result<RepoTreeResponse> {
        run_embedded_repo_tree(request, self.request_metadata()).await
    }

    async fn grep(&self, request: RepoSearchRequest) -> Result<RepoSearchResponse> {
        run_embedded_repo_grep(request, self.request_metadata()).await
    }

    async fn read_file(&self, request: RepoReadFileRequest) -> Result<RepoReadFileResponse> {
        run_embedded_repo_read_file(request, self.request_metadata()).await
    }

    async fn git_log(&self, request: RepoGitLogRequest) -> Result<RepoGitLogResponse> {
        run_embedded_repo_git_log(request, self.request_metadata()).await
    }

    async fn remote_inspect(
        &self,
        request: RepoRemoteInspectRequest,
    ) -> Result<RepoRemoteInspectResponse> {
        run_embedded_repo_remote_inspect(request, self.request_metadata()).await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawOsRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawOsRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl OsRuntime for EmbeddedOpenClawOsRuntime {
    async fn execute(&self, request: OsOperationRequest) -> Result<OsOperationResult> {
        run_embedded_os_execute(request, self.request_metadata()).await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawResearchRuntime {
    provider: ProviderKind,
    model_id: String,
    system_prompt: Option<String>,
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawResearchRuntime {
    pub fn new(
        provider: ProviderKind,
        model_id: impl Into<String>,
        agent_name: impl AsRef<str>,
    ) -> Self {
        let mut metadata = default_embedded_metadata(agent_name.as_ref());
        if provider == ProviderKind::Ollama {
            metadata.insert("ollama_host".to_string(), normalized_ollama_host());
        }
        Self {
            provider,
            model_id: model_id.into(),
            system_prompt: None,
            metadata,
        }
    }

    pub fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        let prompt = system_prompt.into();
        self.system_prompt = if prompt.trim().is_empty() {
            None
        } else {
            Some(prompt)
        };
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl ResearchRuntime for EmbeddedOpenClawResearchRuntime {
    async fn plan(&self, request: ResearchPlanRequest) -> Result<ResearchPlanResponse> {
        run_embedded_research_plan(
            self.provider.clone(),
            &self.model_id,
            self.system_prompt.as_deref(),
            request,
            self.request_metadata(),
        )
        .await
    }

    async fn search(&self, request: ResearchSearchRequest) -> Result<ResearchSearchResponse> {
        run_embedded_research_search(
            self.provider.clone(),
            &self.model_id,
            request,
            self.request_metadata(),
        )
        .await
    }

    async fn inspect(&self, request: ResearchInspectRequest) -> Result<ResearchInspectResponse> {
        run_embedded_research_inspect(
            self.provider.clone(),
            &self.model_id,
            request,
            self.request_metadata(),
        )
        .await
    }

    async fn open_page(
        &self,
        request: ResearchOpenPageRequest,
    ) -> Result<ResearchOpenPageResponse> {
        run_embedded_research_open_page(request, self.request_metadata()).await
    }

    async fn find_in_page(
        &self,
        request: ResearchFindInPageRequest,
    ) -> Result<ResearchFindInPageResponse> {
        run_embedded_research_find_in_page(request, self.request_metadata()).await
    }

    async fn synthesize(
        &self,
        request: ResearchSynthesisRequest,
    ) -> Result<ResearchSynthesisResponse> {
        run_embedded_research_synthesize(
            self.provider.clone(),
            &self.model_id,
            self.system_prompt.as_deref(),
            request,
            self.request_metadata(),
        )
        .await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawBrowserRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawBrowserRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl BrowserRuntime for EmbeddedOpenClawBrowserRuntime {
    async fn start_session(&self, spec: BrowserSessionSpec) -> Result<()> {
        run_embedded_browser_start_session(spec, self.request_metadata()).await
    }

    async fn open(&self, request: BrowserOpenRequest) -> Result<BrowserSnapshot> {
        run_embedded_browser_open(request, self.request_metadata()).await
    }

    async fn snapshot(&self, session_id: &str) -> Result<BrowserSnapshot> {
        run_embedded_browser_snapshot(session_id, self.request_metadata()).await
    }

    async fn interact(&self, request: BrowserInteractRequest) -> Result<BrowserSnapshot> {
        run_embedded_browser_interact(request, self.request_metadata()).await
    }

    async fn download(&self, request: BrowserDownloadRequest) -> Result<BrowserDownloadResult> {
        run_embedded_browser_download(request, self.request_metadata()).await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawDocumentRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawDocumentRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl DocumentRuntime for EmbeddedOpenClawDocumentRuntime {
    async fn read(&self, request: DocumentReadRequest) -> Result<DocumentReadResponse> {
        run_embedded_document_read(request, self.request_metadata()).await
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedOpenClawPluginMcpRuntime {
    metadata: HashMap<String, String>,
}

impl EmbeddedOpenClawPluginMcpRuntime {
    pub fn new(agent_name: impl AsRef<str>) -> Self {
        Self {
            metadata: default_embedded_metadata(agent_name.as_ref()),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn request_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }
}

#[async_trait]
impl PluginMcpRuntime for EmbeddedOpenClawPluginMcpRuntime {
    async fn list_plugins(&self) -> Result<Vec<PluginInfo>> {
        run_embedded_plugin_mcp_list_plugins(self.request_metadata()).await
    }

    async fn list_servers(&self) -> Result<Vec<McpServerInfo>> {
        run_embedded_plugin_mcp_list_servers(self.request_metadata()).await
    }

    async fn resolve_capability(
        &self,
        capability_id: &str,
    ) -> Result<Option<PluginCapabilityInfo>> {
        run_embedded_plugin_mcp_resolve_capability(capability_id, self.request_metadata()).await
    }

    async fn invoke(&self, request: PluginMcpInvokeRequest) -> Result<PluginMcpInvokeResponse> {
        run_embedded_plugin_mcp_invoke(request, self.request_metadata()).await
    }
}

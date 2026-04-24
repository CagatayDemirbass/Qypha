import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { streamSimple, type AssistantMessage, type Api, type Model } from "@mariozechner/pi-ai";
import type { AgentToolResult, StreamFn } from "@mariozechner/pi-agent-core";
import JSON5 from "json5";
import { loadEmbeddedPiMcpConfig } from "../src/agents/embedded-pi-mcp.js";
import { buildEmbeddedCapabilityConfig as buildSharedEmbeddedCapabilityConfig } from "../src/agents/embedded-capability-config.js";
import { createBundleMcpToolRuntime } from "../src/agents/pi-bundle-mcp-tools.js";
import type { OpenClawConfig } from "../src/config/config.js";
import { applyMergePatch } from "../src/config/merge-patch.js";
import { resolveConfigPathCandidate } from "../src/config/paths.js";
import type { ModelApi } from "../src/config/types.models.js";
import { DEFAULT_CONTEXT_TOKENS } from "../src/agents/defaults.js";
import { normalizeModelCompat } from "../src/agents/model-compat.js";
import { buildOllamaModelDefinition, fetchOllamaModels } from "../src/agents/ollama-models.js";
import { createGoogleThinkingPayloadWrapper } from "../src/agents/pi-embedded-runner/google-stream-wrappers.js";
import {
  createOpenAIAttributionHeadersWrapper,
  createOpenAIDefaultTransportWrapper,
} from "../src/agents/pi-embedded-runner/openai-stream-wrappers.js";
import { normalizeToolName } from "../src/agents/tool-policy.js";
import { createWebFetchTool } from "../src/agents/tools/web-fetch.js";
import { createWebSearchTool } from "../src/agents/tools/web-search.js";
import { browserAct, browserNavigate, browserPdfSave } from "../src/browser/client-actions.js";
import {
  browserCreateProfile,
  browserOpenTab,
  browserProfiles,
  browserSnapshot,
  browserStart,
} from "../src/browser/client.js";
import { resolveGoogle31ForwardCompatModel } from "../extensions/google/provider-models.js";
import { extractArchive } from "../src/infra/archive.js";
import { copyToClipboard } from "../src/infra/clipboard.js";
import { getMemorySearchManager } from "../src/memory/index.js";
import { extractPdfContent } from "../src/media/pdf-extract.js";
import { enableConsoleCapture, routeLogsToStderr } from "../src/logging/console.js";
import { inspectBundleMcpRuntimeSupport } from "../src/plugins/bundle-mcp.js";
import { cloneFirstTemplateModel } from "../src/plugins/provider-model-helpers.js";
import { runCommandWithTimeout } from "../src/process/exec.js";
import { normalizeAgentId } from "../src/routing/session-key.js";
import { markdownToIR } from "../src/markdown/ir.js";

type QyphaWorkerCapability =
  | "provider"
  | "research"
  | "browser"
  | "document"
  | "memory"
  | "os"
  | "repo";

type ProviderMessage = {
  role: string;
  content: string;
};

type ProviderGenerateRequest = {
  provider: string;
  model_id: string;
  system_prompt?: string | null;
  messages?: ProviderMessage[];
  metadata?: Record<string, string>;
};

type ProviderHealthcheckRequest = {
  metadata?: Record<string, string>;
};

type ProviderListModelsRequest = {
  provider: string;
  metadata?: Record<string, string>;
};

type ProviderCatalogEntry = {
  provider: "ollama" | "open_ai" | "anthropic" | "gemini" | "unknown";
  model_id: string;
  label: string;
  local: boolean;
  supports_tools?: boolean;
  supports_vision?: boolean;
};

type RepoOverviewRequest = {
  root: string;
  metadata?: Record<string, string>;
};

type RepoTreeRequest = {
  root: string;
  depth?: number | null;
  metadata?: Record<string, string>;
};

type RepoTreeEntry = {
  path: string;
  kind: string;
};

type RepoSearchRequest = {
  root: string;
  pattern: string;
  limit?: number;
  metadata?: Record<string, string>;
};

type RepoSearchMatch = {
  path: string;
  line_number: number;
  line_text: string;
};

type RepoReadFileRequest = {
  path: string;
  metadata?: Record<string, string>;
};

type RepoGitLogRequest = {
  root: string;
  limit?: number;
  metadata?: Record<string, string>;
};

type RepoGitCommitEntry = {
  commit_id: string;
  summary: string;
};

type RepoRemoteInspectRequest = {
  url: string;
  reference?: string | null;
  metadata?: Record<string, string>;
};

type RepoTreeNode = {
  name?: string;
  type?: string;
  children?: RepoTreeNode[];
};

type MemoryWriteRequest = {
  actor_id: string;
  scope: string;
  content: string;
  source_links?: string[];
};

type MemoryEntry = {
  memory_id: string;
  actor_id: string;
  scope: string;
  content: string;
  source_links?: string[];
};

type MemoryGetRequest = {
  actor_id: string;
  memory_id: string;
};

type MemorySearchRequest = {
  actor_id: string;
  query: string;
  limit?: number;
};

type MemoryCompressRequest = {
  actor_id: string;
  scope: string;
};

type MemoryStalenessCheckRequest = {
  actor_id: string;
  memory_id: string;
};

type OsOperationRequest = {
  actor_id: string;
  access_mode: "restricted" | "full_access";
  execution_kind: "typed_operation" | "shell_fallback";
  operation: {
    kind: string;
    [key: string]: unknown;
  };
};

type AgentRunRequest = {
  provider: string;
  model_id: string;
  system_prompt?: string | null;
  prompt: string;
  metadata?: Record<string, string>;
};

type ResearchDisposition =
  | "answer_directly"
  | "search_web"
  | "inspect_specific_sources"
  | "use_browser"
  | "read_document"
  | "inspect_repo";

type ResearchSource = {
  title: string;
  url: string;
  snippet?: string;
  source_kind?: string;
  score?: number;
};

type SourceClassification =
  | "primary"
  | "secondary"
  | "summary"
  | "news"
  | "repo"
  | "paper"
  | "official_doc"
  | "web"
  | "unknown";

type ResearchSourceScope = {
  allowed_domains?: string[];
  prioritized_domains?: string[];
  allow_open_web?: boolean;
  allow_connected_sources?: boolean;
};

type ResearchActionLogEntry = {
  action: string;
  at_ms: number;
  url?: string;
  session_id?: string;
  query?: string;
  note?: string;
};

type ConsultedSourceRecord = {
  source: ResearchSource;
  classification: SourceClassification;
  extraction_mode: string;
  accessed_at_ms: number;
  content_length_chars: number;
  page_ranges?: string[];
  headings?: string[];
  find_queries?: string[];
  notes?: string;
};

type InspectedResearchSource = {
  source: ResearchSource;
  extracted_text: string;
  notes?: string;
  disagreement_flags?: string[];
  consulted_source?: ConsultedSourceRecord;
};

type ResearchFollowUpCandidate = {
  source: ResearchSource;
  label: string;
  score: number;
  rationale: string;
};

type ResearchFetchedInspection = {
  displayText: string;
  plainText: string;
  headings: string[];
  extractor: string;
  warning?: string;
  contentType?: string;
  notes: string;
  linkCandidates: ResearchFollowUpCandidate[];
};

type ResearchPlanRequest = {
  provider: string;
  model_id: string;
  query: string;
  current_answer_draft?: string | null;
  local_context_available?: boolean;
  system_prompt?: string | null;
  metadata?: Record<string, string>;
};

type ResearchSearchRequest = {
  provider: string;
  model_id: string;
  query: string;
  recency_required?: boolean;
  technical_only?: boolean;
  max_results?: number;
  scope?: ResearchSourceScope;
  metadata?: Record<string, string>;
};

type ResearchInspectRequest = {
  provider: string;
  model_id: string;
  query: string;
  sources: ResearchSource[];
  max_sources?: number;
  scope?: ResearchSourceScope;
  metadata?: Record<string, string>;
};

type ResearchOpenPageRequest = {
  session_id: string;
  source: ResearchSource;
  scope?: ResearchSourceScope;
  metadata?: Record<string, string>;
};

type ResearchPageMatch = {
  line_number: number;
  heading?: string;
  excerpt: string;
};

type ResearchFindInPageRequest = {
  session_id: string;
  query: string;
  source?: ResearchSource | null;
  url?: string | null;
  max_matches?: number;
  scope?: ResearchSourceScope;
  metadata?: Record<string, string>;
};

type ResearchSynthesizeRequest = {
  provider: string;
  model_id: string;
  query: string;
  sources?: ResearchSource[];
  inspected_sources?: InspectedResearchSource[];
  consulted_sources?: ConsultedSourceRecord[];
  desired_format?: string | null;
  system_prompt?: string | null;
  metadata?: Record<string, string>;
};

type BrowserSessionMode = "ephemeral" | "persistent";

type BrowserSessionSpec = {
  session_id: string;
  mode: BrowserSessionMode;
  allowed_domains?: string[];
  metadata?: Record<string, string>;
};

type BrowserOpenRequest = {
  session_id: string;
  url: string;
  metadata?: Record<string, string>;
};

type BrowserInteractRequest = {
  session_id: string;
  action: string;
  target?: string | null;
  value?: string | null;
  metadata?: Record<string, string>;
};

type BrowserDownloadRequest = {
  session_id: string;
  url: string;
  destination?: string | null;
  metadata?: Record<string, string>;
};

type DocumentReadRequest = {
  path: string;
  metadata?: Record<string, string>;
};

type DocumentSection = {
  heading: string;
  body: string;
};

type PluginMcpListRequest = {
  metadata?: Record<string, string>;
};

type PluginMcpResolveRequest = {
  capability_id: string;
  metadata?: Record<string, string>;
};

type PluginMcpInvokeRequest = {
  capability_id: string;
  args_json?: string;
  metadata?: Record<string, string>;
};

type PluginInfo = {
  plugin_id: string;
  enabled: boolean;
};

type McpServerInfo = {
  server_name: string;
  plugin_id?: string;
};

type PluginCapabilityInfo = {
  capability_id: string;
  kind: string;
  plugin_id?: string;
  server_name?: string;
};

type BundledCapabilityRegistryEntry = {
  dir?: unknown;
  enabled?: unknown;
};

type RegisteredBundledCapabilityPlugin = {
  pluginId: string;
  rootDir: string;
};

type WorkerRequest =
  | {
      op: "hello";
    }
  | {
      op: "provider_healthcheck";
      payload: ProviderHealthcheckRequest;
    }
  | {
      op: "provider_list_models";
      payload: ProviderListModelsRequest;
    }
  | {
      op: "provider_generate";
      payload: ProviderGenerateRequest;
    }
  | {
      op: "memory_get";
      payload: {
        request: MemoryGetRequest;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "memory_write";
      payload: {
        request: MemoryWriteRequest;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "memory_search";
      payload: {
        request: MemorySearchRequest;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "memory_compress";
      payload: {
        request: MemoryCompressRequest;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "memory_staleness_check";
      payload: {
        request: MemoryStalenessCheckRequest;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "repo_overview";
      payload: RepoOverviewRequest;
    }
  | {
      op: "repo_tree";
      payload: RepoTreeRequest;
    }
  | {
      op: "repo_grep";
      payload: RepoSearchRequest;
    }
  | {
      op: "repo_read_file";
      payload: RepoReadFileRequest;
    }
  | {
      op: "repo_git_log";
      payload: RepoGitLogRequest;
    }
  | {
      op: "repo_remote_inspect";
      payload: RepoRemoteInspectRequest;
    }
  | {
      op: "os_execute";
      payload: {
        request: OsOperationRequest;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "agent_run";
      payload: AgentRunRequest;
    }
  | {
      op: "research_plan";
      payload: ResearchPlanRequest;
    }
  | {
      op: "research_search";
      payload: ResearchSearchRequest;
    }
  | {
      op: "research_inspect";
      payload: ResearchInspectRequest;
    }
  | {
      op: "research_open_page";
      payload: ResearchOpenPageRequest;
    }
  | {
      op: "research_find_in_page";
      payload: ResearchFindInPageRequest;
    }
  | {
      op: "research_synthesize";
      payload: ResearchSynthesizeRequest;
    }
  | {
      op: "browser_start_session";
      payload: BrowserSessionSpec;
    }
  | {
      op: "browser_open";
      payload: BrowserOpenRequest;
    }
  | {
      op: "browser_snapshot";
      payload: {
        session_id: string;
        metadata?: Record<string, string>;
      };
    }
  | {
      op: "browser_interact";
      payload: BrowserInteractRequest;
    }
  | {
      op: "browser_download";
      payload: BrowserDownloadRequest;
    }
  | {
      op: "document_read";
      payload: DocumentReadRequest;
    }
  | {
      op: "plugin_mcp_list_plugins";
      payload: PluginMcpListRequest;
    }
  | {
      op: "plugin_mcp_list_servers";
      payload: PluginMcpListRequest;
    }
  | {
      op: "plugin_mcp_resolve_capability";
      payload: PluginMcpResolveRequest;
    }
  | {
      op: "plugin_mcp_invoke";
      payload: PluginMcpInvokeRequest;
    };

type WorkerSuccess =
  | {
      ok: true;
    }
  | {
      ok: true;
      worker: "qypha-embedded-runtime";
      version: 1;
      capabilities: QyphaWorkerCapability[];
    }
  | {
      ok: true;
      catalog: ProviderCatalogEntry[];
    }
  | {
      ok: true;
      memory_entry?: MemoryEntry;
    }
  | {
      ok: true;
      memory_entries: MemoryEntry[];
    }
  | {
      ok: true;
      memory_id: string;
      stale: boolean;
      rationale?: string;
    }
  | {
      ok: true;
      root: string;
      vcs?: string;
      branch?: string;
      dirty: boolean;
      changed_files: string[];
    }
  | {
      ok: true;
      root: string;
      entries: RepoTreeEntry[];
    }
  | {
      ok: true;
      root: string;
      repo_matches: RepoSearchMatch[];
    }
  | {
      ok: true;
      path: string;
      file_content: string;
    }
  | {
      ok: true;
      root: string;
      commits: RepoGitCommitEntry[];
    }
  | {
      ok: true;
      url: string;
      summary?: string;
      candidate_files: string[];
    }
  | {
      ok: true;
      status: "accepted" | "running" | "blocked" | "completed" | "failed";
      stdout?: string;
      stderr?: string;
      paths: string[];
    }
  | {
      ok: true;
      model_id: string;
      output_text: string;
      finish_reason?: string;
    }
  | {
      ok: true;
      disposition: ResearchDisposition;
      rationale: string;
      planned_steps: string[];
    }
  | {
      ok: true;
      query: string;
      sources: ResearchSource[];
      action_log: ResearchActionLogEntry[];
    }
  | {
      ok: true;
      query: string;
      inspected_sources: InspectedResearchSource[];
      consulted_sources: ConsultedSourceRecord[];
      action_log: ResearchActionLogEntry[];
    }
  | {
      ok: true;
      session_id: string;
      url: string;
      markdown: string;
      consulted_source: ConsultedSourceRecord;
      action_log: ResearchActionLogEntry[];
    }
  | {
      ok: true;
      session_id: string;
      url: string;
      query: string;
      matches: ResearchPageMatch[];
      consulted_source?: ConsultedSourceRecord;
      action_log: ResearchActionLogEntry[];
    }
  | {
      ok: true;
      answer: string;
      uncertainty?: string;
      citations: string[];
      sources_used: ConsultedSourceRecord[];
    }
  | {
      ok: true;
      session_id: string;
      url?: string;
      markdown?: string;
      path?: string;
    }
  | {
      ok: true;
      path: string;
      sections: DocumentSection[];
    }
  | {
      ok: true;
      plugins: PluginInfo[];
    }
  | {
      ok: true;
      servers: McpServerInfo[];
    }
  | {
      ok: true;
      capability?: PluginCapabilityInfo;
    }
  | {
      ok: true;
      capability_id: string;
      output_json: string;
    };

type WorkerFailure = {
  ok: false;
  error: string;
};

type BrowserSnapshotSuccess = {
  ok: true;
  session_id: string;
  url?: string;
  markdown: string;
};

type BrowserSessionState = {
  sessionId: string;
  mode: BrowserSessionMode;
  allowedDomains: string[];
  profile: string;
  targetId?: string;
  url?: string;
};

type BundleMcpCapabilityState = {
  capability: PluginCapabilityInfo;
  tool: Awaited<ReturnType<typeof createBundleMcpToolRuntime>>["tools"][number];
};

type BundleMcpState = {
  workspaceDir: string;
  allowedDirs: string[];
  fingerprint: string;
  cfg: OpenClawConfig;
  runtime?: Awaited<ReturnType<typeof createBundleMcpToolRuntime>>;
  plugins: PluginInfo[];
  servers: McpServerInfo[];
  capabilities: Map<string, BundleMcpCapabilityState>;
};

type WorkerRuntimeStatusResult = {
  ok: true;
  status: "accepted" | "running" | "blocked" | "completed" | "failed";
  stdout?: string;
  stderr?: string;
  paths: string[];
};

type QyphaMemoryPointer = {
  v: 1;
  actor_id: string;
  scope: string;
  path: string;
  from: number;
  lines: number;
  content_hash: string;
};

function debugLog(message: string) {
  const logPath = process.env.QYPHA_EMBEDDED_DEBUG_LOG?.trim();
  if (!logPath) {
    return;
  }
  try {
    fs.appendFileSync(logPath, `${new Date().toISOString()} ${message}\n`);
  } catch {
    // ignore debug logging failures
  }
}

debugLog("worker:module_loaded");
routeLogsToStderr();
enableConsoleCapture();

type RuntimeModel = Omit<Model<Api>, "api"> & {
  api: ModelApi;
  baseUrl?: string;
  contextWindow?: number;
  maxTokens?: number;
  reasoning?: boolean;
  input?: Array<"text" | "image">;
};

type EmbeddedFetchTool = NonNullable<Awaited<ReturnType<typeof createWebFetchTool>>>;

type EmbeddedModelRegistry = {
  find(provider: string, modelId: string): RuntimeModel | null;
};

type EmbeddedProviderAdapter = {
  id: "ollama" | "openai" | "anthropic" | "google";
  resolveModel: (modelId: string, metadata?: Record<string, string>) => RuntimeModel;
  wrapStreamFn?: (streamFn: StreamFn) => StreamFn;
  missingAuthMessage: () => string;
};

const CAPABILITIES: QyphaWorkerCapability[] = [
  "provider",
  "research",
  "browser",
  "document",
  "memory",
  "os",
  "repo",
];

const browserSessions = new Map<string, BrowserSessionState>();
let bundleMcpState: BundleMcpState | null = null;

const OPENAI_BASE_URL = "https://api.openai.com/v1";
const ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1";
const GOOGLE_BASE_URL = "https://generativelanguage.googleapis.com/v1beta";
const OLLAMA_BASE_URL = "http://127.0.0.1:11434";

const OPENAI_GPT_54_MODEL_ID = "gpt-5.4";
const OPENAI_GPT_54_PRO_MODEL_ID = "gpt-5.4-pro";
const OPENAI_GPT_54_MINI_MODEL_ID = "gpt-5.4-mini";
const OPENAI_GPT_54_NANO_MODEL_ID = "gpt-5.4-nano";
const OPENAI_GPT_54_CONTEXT_TOKENS = 1_050_000;
const OPENAI_GPT_54_MAX_TOKENS = 128_000;
const OPENAI_GPT_54_TEMPLATE_MODEL_IDS = ["gpt-5.2"] as const;
const OPENAI_GPT_54_PRO_TEMPLATE_MODEL_IDS = ["gpt-5.2-pro", "gpt-5.2"] as const;
const OPENAI_GPT_54_MINI_TEMPLATE_MODEL_IDS = ["gpt-5-mini"] as const;
const OPENAI_GPT_54_NANO_TEMPLATE_MODEL_IDS = ["gpt-5-nano", "gpt-5-mini"] as const;

const ANTHROPIC_OPUS_46_MODEL_ID = "claude-opus-4-6";
const ANTHROPIC_OPUS_46_DOT_MODEL_ID = "claude-opus-4.6";
const ANTHROPIC_OPUS_TEMPLATE_MODEL_IDS = ["claude-opus-4-5", "claude-opus-4.5"] as const;
const ANTHROPIC_SONNET_46_MODEL_ID = "claude-sonnet-4-6";
const ANTHROPIC_SONNET_46_DOT_MODEL_ID = "claude-sonnet-4.6";
const ANTHROPIC_SONNET_TEMPLATE_MODEL_IDS = ["claude-sonnet-4-5", "claude-sonnet-4.5"] as const;

function normalizeProviderId(provider: string): EmbeddedProviderAdapter["id"] {
  const normalized = provider.trim().toLowerCase();
  if (normalized === "claude") {
    return "anthropic";
  }
  if (normalized === "gemini") {
    return "google";
  }
  if (
    normalized === "ollama" ||
    normalized === "openai" ||
    normalized === "anthropic" ||
    normalized === "google"
  ) {
    return normalized;
  }
  throw new Error(`Unsupported embedded provider: ${provider}`);
}

function providerApi(provider: EmbeddedProviderAdapter["id"]) {
  switch (provider) {
    case "ollama":
      return "openai-completions" as const;
    case "anthropic":
      return "anthropic-messages" as const;
    case "google":
      return "google-generative-ai" as const;
    case "openai":
    default:
      return "openai-responses" as const;
  }
}

function providerBaseUrl(
  provider: EmbeddedProviderAdapter["id"],
  metadata?: Record<string, string>,
) {
  switch (provider) {
    case "ollama":
      return (
        metadata?.ollama_host?.trim() ||
        process.env.OLLAMA_HOST?.trim() ||
        process.env.QYPHA_OLLAMA_HOST?.trim() ||
        OLLAMA_BASE_URL
      )
        .replace(/\/+$/, "")
        .replace(/\/v1$/i, "")
        .concat("/v1");
    case "anthropic":
      return metadata?.anthropic_base_url?.trim() || ANTHROPIC_BASE_URL;
    case "google":
      return metadata?.google_base_url?.trim() || GOOGLE_BASE_URL;
    case "openai":
    default:
      return metadata?.openai_base_url?.trim() || OPENAI_BASE_URL;
  }
}

function buildRuntimeModel(
  provider: EmbeddedProviderAdapter["id"],
  modelId: string,
  metadata?: Record<string, string>,
): RuntimeModel {
  const multimodal = provider === "openai" || provider === "anthropic" || provider === "google";
  return {
    id: modelId,
    name: modelId,
    provider,
    api: providerApi(provider),
    baseUrl: providerBaseUrl(provider, metadata),
    reasoning: provider !== "ollama",
    input: multimodal ? ["text", "image"] : ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: DEFAULT_CONTEXT_TOKENS,
    maxTokens: DEFAULT_CONTEXT_TOKENS,
    compat:
      provider === "ollama"
        ? {
            supportsDeveloperRole: false,
            supportsReasoningEffort: false,
            supportsStore: false,
          }
        : undefined,
  } as RuntimeModel;
}

function staticTemplateModels(
  provider: EmbeddedProviderAdapter["id"],
  metadata?: Record<string, string>,
): RuntimeModel[] {
  switch (provider) {
    case "openai":
      return ["gpt-5.2", "gpt-5.2-pro", "gpt-5-mini", "gpt-5-nano"].map((modelId) =>
        buildRuntimeModel(provider, modelId, metadata),
      );
    case "anthropic":
      return [
        "claude-opus-4-5",
        "claude-opus-4.5",
        "claude-sonnet-4-5",
        "claude-sonnet-4.5",
        "claude-haiku-4-5",
      ].map((modelId) => buildRuntimeModel(provider, modelId, metadata));
    case "google":
      return ["gemini-3-pro-preview", "gemini-3-flash-preview"].map((modelId) =>
        buildRuntimeModel(provider, modelId, metadata),
      );
    default:
      return [];
  }
}

function createModelRegistry(
  provider: EmbeddedProviderAdapter["id"],
  modelId: string,
  metadata?: Record<string, string>,
): EmbeddedModelRegistry {
  const registry = new Map<string, RuntimeModel>();
  for (const model of staticTemplateModels(provider, metadata)) {
    registry.set(`${provider}:${model.id.toLowerCase()}`, model);
  }
  const selected = buildRuntimeModel(provider, modelId, metadata);
  registry.set(`${provider}:${selected.id.toLowerCase()}`, selected);
  return {
    find(requestProvider: string, requestedModelId: string) {
      const key = `${normalizeProviderId(requestProvider)}:${requestedModelId.trim().toLowerCase()}`;
      return registry.get(key) ?? null;
    },
  };
}

function embeddedWorkerRuntimeRootDir(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

function resolveEmbeddedStateRootDir(): string {
  const explicitStateDir =
    normalizeOptionalString(process.env.QYPHA_RUNTIME_STATE_DIR) ??
    normalizeOptionalString(process.env.OPENCLAW_STATE_DIR);
  const explicitHomeDir =
    normalizeOptionalString(process.env.QYPHA_RUNTIME_HOME) ??
    normalizeOptionalString(process.env.OPENCLAW_HOME);
  return explicitStateDir
    ? path.resolve(explicitStateDir)
    : explicitHomeDir
      ? path.resolve(explicitHomeDir, ".qypha-runtime")
      : path.resolve(embeddedWorkerRuntimeRootDir(), ".runtime-state");
}

function resolveEmbeddedActorContext(params: {
  actorId?: string;
  metadata?: Record<string, string>;
}): { actorId: string; agentId: string } {
  const actorId =
    normalizeOptionalString(params.actorId) ??
    resolveMetadataString(params.metadata, "agent_name") ??
    "main";
  return {
    actorId,
    agentId: normalizeAgentId(actorId),
  };
}

function resolveEmbeddedActorDir(params: {
  actorId: string;
  metadata?: Record<string, string>;
}): string {
  const metadataAgentDir = resolveMetadataString(params.metadata, "agent_dir");
  if (metadataAgentDir) {
    const metadataAgentId = normalizeAgentId(
      resolveMetadataString(params.metadata, "agent_name") ?? params.actorId,
    );
    if (metadataAgentId === params.actorId) {
      return path.resolve(metadataAgentDir);
    }
    return path.resolve(path.dirname(path.resolve(metadataAgentDir)), params.actorId);
  }

  const stateRoot = resolveEmbeddedStateRootDir();
  return path.resolve(stateRoot, "agents", params.actorId, "agent");
}

function buildEmbeddedActorCapabilityConfig(params: {
  actorId?: string;
  metadata?: Record<string, string>;
  overlay?: OpenClawConfig;
}): OpenClawConfig {
  const actor = resolveEmbeddedActorContext({
    actorId: params.actorId,
    metadata: params.metadata,
  });
  const workspaceDir = resolveWorkspaceDir(params.metadata, actor.actorId);
  const agentSkillsDir = resolveMetadataString(params.metadata, "qypha_agent_skills_dir");
  const baseConfig: OpenClawConfig = {
    plugins: {
      enabled: true,
      slots: {
        memory: "memory-core",
      },
    },
    agents: {
      defaults: {
        workspace: workspaceDir,
      },
      list: [
        {
          id: actor.agentId,
          default: true,
          workspace: workspaceDir,
          agentDir: resolveEmbeddedActorDir({
            actorId: actor.agentId,
            metadata: params.metadata,
          }),
          runtime: {
            type: "embedded",
          },
        },
      ],
    },
    ...(agentSkillsDir
      ? {
          skills: {
            load: {
              extraDirs: [path.resolve(agentSkillsDir)],
            },
          },
        }
      : {}),
  };
  const mergedBase =
    params.overlay !== undefined
      ? (applyMergePatch(baseConfig, params.overlay) as OpenClawConfig)
      : baseConfig;
  return buildSharedEmbeddedCapabilityConfig({
    workspaceDir,
    runtimeRootDir: embeddedWorkerRuntimeRootDir(),
    baseConfig: mergedBase,
  });
}

function buildEmbeddedRunConfig(
  provider: EmbeddedProviderAdapter["id"],
  modelId: string,
  metadata?: Record<string, string>,
): OpenClawConfig {
  const runtimeModel = PROVIDERS[provider].resolveModel(modelId, metadata);
  const modelRef = `${provider}/${runtimeModel.id}`;
  const overlay: OpenClawConfig = {
    agents: {
      defaults: {
        model: {
          primary: modelRef,
        },
        imageModel: {
          primary: modelRef,
        },
        pdfModel: {
          primary: modelRef,
        },
        pdfMaxBytesMb: 25,
        pdfMaxPages: 64,
      },
    },
    tools: {
      web: {
        fetch: {
          maxCharsCap: 120_000,
          maxResponseBytes: 10_000_000,
          timeoutSeconds: 45,
          readability: true,
          firecrawl: {
            enabled: true,
            timeoutSeconds: 45,
          },
        },
      },
    },
    models: {
      mode: "replace",
      providers: {
        [provider]: {
          baseUrl: runtimeModel.baseUrl ?? providerBaseUrl(provider, metadata),
          api: runtimeModel.api,
          models: [
            {
              id: runtimeModel.id,
              name: runtimeModel.name ?? runtimeModel.id,
              api: runtimeModel.api,
              reasoning: runtimeModel.reasoning ?? provider !== "ollama",
              input: runtimeModel.input ?? ["text"],
              cost: runtimeModel.cost ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
              contextWindow: runtimeModel.contextWindow ?? DEFAULT_CONTEXT_TOKENS,
              maxTokens: runtimeModel.maxTokens ?? DEFAULT_CONTEXT_TOKENS,
              ...(runtimeModel.compat ? { compat: runtimeModel.compat } : {}),
            },
          ],
        },
      },
    },
  };
  return buildEmbeddedActorCapabilityConfig({
    actorId: resolveMetadataString(metadata, "agent_name"),
    metadata,
    overlay,
  });
}

function buildEmbeddedCapabilityConfig(workspaceDir?: string): OpenClawConfig {
  return buildSharedEmbeddedCapabilityConfig({
    workspaceDir: workspaceDir ? path.resolve(workspaceDir) : resolveWorkspaceDir(undefined),
    runtimeRootDir: embeddedWorkerRuntimeRootDir(),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stableSerialize(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableSerialize(entry)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort((left, right) => left.localeCompare(right))
      .map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

async function loadOwnerManagedCapabilityBaseConfig(): Promise<OpenClawConfig | undefined> {
  try {
    const configPath = resolveConfigPathCandidate(process.env);
    const raw = await fsp.readFile(configPath, "utf-8");
    const trimmed = raw.trim();
    if (!trimmed) {
      return undefined;
    }
    const parsed = JSON5.parse(trimmed) as unknown;
    if (isRecord(parsed)) {
      return parsed as OpenClawConfig;
    }
  } catch {
    // Fall back to bundled defaults when no owner-managed config exists yet.
  }
  return undefined;
}

async function resolveEmbeddedCapabilityConfig(workspaceDir?: string): Promise<{
  cfg: OpenClawConfig;
  fingerprint: string;
}> {
  const baseConfig = await loadOwnerManagedCapabilityBaseConfig();
  const cfg = buildSharedEmbeddedCapabilityConfig({
    workspaceDir,
    runtimeRootDir: path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
    baseConfig,
  });
  const pluginConfig = isRecord(cfg.plugins) ? cfg.plugins : {};
  const fingerprint = stableSerialize({
    mcpServers: cfg.mcp?.servers ?? {},
    pluginLoad: isRecord(pluginConfig.load) ? pluginConfig.load : {},
    pluginsEnabled: pluginConfig.enabled ?? null,
  });
  return { cfg, fingerprint };
}

function resolveBundledCapabilityPluginRoot(): string {
  const workerRootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  return path.resolve(workerRootDir, "internal/bundled-mcp-plugins");
}

function resolveBundledCapabilityRegistryEntries(): BundledCapabilityRegistryEntry[] {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot();
  const registryPath = path.resolve(bundledPluginsDir, "registry.json");
  if (!fs.existsSync(registryPath)) {
    return [];
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(registryPath, "utf-8")) as {
      plugins?: unknown;
    };
    return Array.isArray(parsed.plugins) ? parsed.plugins : [];
  } catch {
    return [];
  }
}

function resolveBundledCapabilityPluginLoadPaths(): string[] {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot();
  const registryEntries = resolveBundledCapabilityRegistryEntries();
  const enabledPluginDirs = registryEntries
    .filter(
      (entry): entry is { dir: string; enabled?: unknown } =>
        !!entry && typeof entry.dir === "string" && entry.dir.trim().length > 0,
    )
    .filter((entry) => entry.enabled !== false)
    .map((entry) => path.resolve(bundledPluginsDir, entry.dir));
  if (enabledPluginDirs.length > 0) {
    return enabledPluginDirs.filter((entry) => fs.existsSync(entry));
  }
  if (!fs.existsSync(bundledPluginsDir)) {
    return [];
  }
  return [bundledPluginsDir];
}

function buildBundledCapabilityMcpServers(
  workspaceDir?: string,
  allowedDirs?: Iterable<string>,
): Record<string, Record<string, unknown>> {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot();
  const resolvedWorkspaceDir = workspaceDir
    ? path.resolve(workspaceDir)
    : resolveWorkspaceDir(undefined);
  const filesystemAllowedDirs = Array.from(
    new Set([
      resolvedWorkspaceDir,
      ...Array.from(allowedDirs ?? [], (entry) => path.resolve(entry)),
    ]),
  );
  const filesystemServerPath = path.resolve(
    bundledPluginsDir,
    "filesystem-server",
    "servers",
    "filesystem-server.mjs",
  );
  const gitLauncherPath = path.resolve(
    bundledPluginsDir,
    "git-server",
    "servers",
    "git-server-launcher.mjs",
  );
  const fetchLauncherPath = path.resolve(
    bundledPluginsDir,
    "fetch-server",
    "servers",
    "fetch-server-launcher.mjs",
  );
  const playwrightCliPath = path.resolve(
    bundledPluginsDir,
    "playwright-mcp",
    "vendor",
    "playwright-mcp",
    "package",
    "cli.js",
  );
  const playwrightBrowsersPath = path.resolve(
    bundledPluginsDir,
    "playwright-mcp",
    "vendor",
    "ms-playwright",
  );
  const servers: Record<string, Record<string, unknown>> = {
    filesystem: {
      command: process.execPath,
      args: [filesystemServerPath, ...filesystemAllowedDirs],
      cwd: resolvedWorkspaceDir,
    },
  };

  servers.git = {
    command: process.execPath,
    args: [gitLauncherPath],
  };

  servers.fetch = {
    command: process.execPath,
    args: [fetchLauncherPath],
  };

  const playwrightArgs = [
    playwrightCliPath,
    "--browser",
    "chromium",
    "--isolated",
    "--headless",
    "--output-dir",
    resolveBundledPlaywrightOutputDir(),
  ];
  if (
    normalizeOptionalString(process.env.QYPHA_PLAYWRIGHT_NO_SANDBOX) === "1" ||
    (process.platform === "linux" && typeof process.getuid === "function" && process.getuid() === 0)
  ) {
    playwrightArgs.push("--no-sandbox");
  }
  servers.playwright = {
    command: process.execPath,
    args: playwrightArgs,
    env: {
      PLAYWRIGHT_BROWSERS_PATH: playwrightBrowsersPath,
    },
  };

  return servers;
}

function loadRegisteredBundledCapabilityPlugins(): RegisteredBundledCapabilityPlugin[] {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot();
  return resolveBundledCapabilityRegistryEntries()
    .filter(
      (entry): entry is { dir: string; enabled?: unknown } =>
        !!entry &&
        typeof entry.dir === "string" &&
        entry.dir.trim().length > 0 &&
        entry.enabled !== false,
    )
    .map((entry) => {
      const rootDir = path.resolve(bundledPluginsDir, entry.dir);
      const manifestPath = path.resolve(rootDir, ".claude-plugin", "plugin.json");
      let pluginId = entry.dir.trim();
      if (fs.existsSync(manifestPath)) {
        try {
          const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf-8")) as {
            name?: unknown;
          };
          if (typeof parsed.name === "string" && parsed.name.trim()) {
            pluginId = parsed.name.trim();
          }
        } catch {
          // Fall back to the directory name when the manifest cannot be parsed.
        }
      }
      return { pluginId, rootDir };
    })
    .filter((entry) => fs.existsSync(entry.rootDir));
}

function resolveBundledPlaywrightOutputDir(): string {
  const explicitStateDir =
    normalizeOptionalString(process.env.QYPHA_RUNTIME_STATE_DIR) ??
    normalizeOptionalString(process.env.OPENCLAW_STATE_DIR);
  const explicitHomeDir =
    normalizeOptionalString(process.env.QYPHA_RUNTIME_HOME) ??
    normalizeOptionalString(process.env.OPENCLAW_HOME);
  const stateRoot = explicitStateDir
    ? path.resolve(explicitStateDir)
    : explicitHomeDir
      ? path.resolve(explicitHomeDir, ".qypha-runtime")
      : path.resolve(resolveBundledCapabilityPluginRoot(), ".runtime-state");
  return path.resolve(stateRoot, "playwright-mcp-output");
}

function toRustProviderKindId(
  provider: EmbeddedProviderAdapter["id"],
): ProviderCatalogEntry["provider"] {
  switch (provider) {
    case "openai":
      return "open_ai";
    case "anthropic":
      return "anthropic";
    case "google":
      return "gemini";
    case "ollama":
      return "ollama";
    default:
      return "unknown";
  }
}

function toProviderCatalogEntry(
  provider: EmbeddedProviderAdapter["id"],
  model: { id: string; name?: string; input?: Array<"text" | "image"> },
  opts?: { local?: boolean; supportsTools?: boolean },
): ProviderCatalogEntry {
  return {
    provider: toRustProviderKindId(provider),
    model_id: model.id,
    label: model.name?.trim() || model.id,
    local: opts?.local ?? provider === "ollama",
    supports_tools: opts?.supportsTools ?? provider !== "ollama",
    supports_vision: Array.isArray(model.input) && model.input.includes("image"),
  };
}

function buildEmbeddedRuntimeConfig(
  provider: EmbeddedProviderAdapter["id"],
  modelId: string,
  metadata?: Record<string, string>,
): OpenClawConfig {
  return buildEmbeddedRunConfig(provider, modelId, metadata);
}

function normalizeOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function unwrapExternalContentText(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) {
    return undefined;
  }
  const withoutMarkers = trimmed
    .replace(/<<<EXTERNAL_UNTRUSTED_CONTENT[^>]*>>>/g, "")
    .replace(/<<<END_EXTERNAL_UNTRUSTED_CONTENT[^>]*>>>/g, "")
    .trim();
  return withoutMarkers.replace(/^Source:[^\n]*\n---\n?/m, "").trim();
}

function coerceNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stripJsonCodeFence(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith("```")) {
    return trimmed;
  }
  const lines = trimmed.split(/\r?\n/);
  if (lines.length < 2) {
    return trimmed;
  }
  lines.shift();
  if (lines.at(-1)?.trim() === "```") {
    lines.pop();
  }
  return lines.join("\n").trim();
}

function parseJsonFromModel<T>(text: string): T {
  const trimmed = stripJsonCodeFence(text);
  const candidates = [
    trimmed,
    trimmed.slice(
      Math.max(0, trimmed.indexOf("{")),
      trimmed.lastIndexOf("}") >= 0 ? trimmed.lastIndexOf("}") + 1 : trimmed.length,
    ),
    trimmed.slice(
      Math.max(0, trimmed.indexOf("[")),
      trimmed.lastIndexOf("]") >= 0 ? trimmed.lastIndexOf("]") + 1 : trimmed.length,
    ),
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate) as T;
    } catch {
      // try next candidate
    }
  }
  throw new Error("Model returned invalid JSON for structured research output");
}

function normalizeResearchDisposition(value: unknown): ResearchDisposition {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  switch (normalized) {
    case "answer_directly":
    case "answer-directly":
    case "direct":
      return "answer_directly";
    case "inspect_specific_sources":
    case "inspect-specific-sources":
    case "inspect_sources":
      return "inspect_specific_sources";
    case "use_browser":
    case "use-browser":
    case "browser":
      return "use_browser";
    case "read_document":
    case "read-document":
    case "document":
    case "read_pdf":
      return "read_document";
    case "inspect_repo":
    case "inspect-repo":
    case "repo":
      return "inspect_repo";
    case "search_web":
    case "search-web":
    case "search":
    default:
      return "search_web";
  }
}

function looksLikeCasualPrompt(prompt: string): boolean {
  const normalized = prompt.trim().toLowerCase();
  if (!normalized) {
    return true;
  }
  if (normalized.length > 120) {
    return false;
  }
  return /^(hi|hello|hey|yo|thanks|thank you|thx|who are you|what are you|how are you|good morning|good evening)\b/.test(
    normalized,
  );
}

function promptContainsUrl(prompt: string): boolean {
  return /(https?:\/\/\S+|www\.\S+|arxiv\.org\/|doi\.org\/|github\.com\/)/i.test(prompt);
}

function looksLikePaperResearchPrompt(prompt: string): boolean {
  return /\b(arxiv|doi|research paper|paper|preprint|literature review|survey paper|methodology|results section|supplementary|appendix|citation|citations|study|studies|pdf)\b/i.test(
    prompt,
  );
}

function looksLikeRepoPrompt(prompt: string): boolean {
  return /\b(github|repo|repository|codebase|source code|project files|read this code|inspect this code|git diff|commit|branch|pull request|readme)\b/i.test(
    prompt,
  );
}

function looksLikeBrowserPrompt(prompt: string): boolean {
  return /\b(browser|website|web app|click|fill form|login|sign in|dashboard|tab|navigate|open page|rendered page|js-heavy)\b/i.test(
    prompt,
  );
}

function looksLikeCurrentInfoPrompt(prompt: string): boolean {
  return /\b(latest|most recent|today|current|currently|news|newest|this week|this month|as of now|recently)\b/i.test(
    prompt,
  );
}

function looksLikeResearchTaskPrompt(prompt: string): boolean {
  return /\b(research|investigate|analyze|analyse|compare|look up|find sources|verify|fact check|deep dive|survey)\b/i.test(
    prompt,
  );
}

function shouldRunResearchPlannerForPrompt(prompt: string): boolean {
  if (looksLikeCasualPrompt(prompt)) {
    return false;
  }
  return (
    promptContainsUrl(prompt) ||
    looksLikePaperResearchPrompt(prompt) ||
    looksLikeRepoPrompt(prompt) ||
    looksLikeBrowserPrompt(prompt) ||
    looksLikeCurrentInfoPrompt(prompt) ||
    looksLikeResearchTaskPrompt(prompt) ||
    prompt.trim().length >= 140
  );
}

function inferHeuristicResearchDisposition(prompt: string): ResearchDisposition | null {
  if (looksLikeCasualPrompt(prompt)) {
    return "answer_directly";
  }
  if (looksLikePaperResearchPrompt(prompt)) {
    return "read_document";
  }
  if (looksLikeRepoPrompt(prompt)) {
    return "inspect_repo";
  }
  if (looksLikeBrowserPrompt(prompt)) {
    return "use_browser";
  }
  if (promptContainsUrl(prompt)) {
    return "inspect_specific_sources";
  }
  if (looksLikeCurrentInfoPrompt(prompt) || looksLikeResearchTaskPrompt(prompt)) {
    return "search_web";
  }
  return null;
}

function dispositionPriority(disposition: ResearchDisposition): number {
  switch (disposition) {
    case "answer_directly":
      return 0;
    case "search_web":
      return 1;
    case "inspect_specific_sources":
      return 2;
    case "use_browser":
      return 3;
    case "inspect_repo":
      return 4;
    case "read_document":
      return 5;
  }
}

function mergeResearchDisposition(params: {
  prompt: string;
  modelDisposition?: ResearchDisposition;
}): {
  disposition: ResearchDisposition;
  heuristicDisposition?: ResearchDisposition;
  heuristicRationale?: string;
} {
  const heuristicDisposition = inferHeuristicResearchDisposition(params.prompt);
  const heuristicRationale =
    heuristicDisposition === "read_document"
      ? "The prompt looks like a paper/PDF/literature-review request, so primary-document inspection is required."
      : heuristicDisposition === "inspect_repo"
        ? "The prompt looks repository/code-centric, so repo inspection should happen before answering."
        : heuristicDisposition === "use_browser"
          ? "The prompt appears browser/web-app centric, so browser inspection is safer than plain fetch."
          : heuristicDisposition === "inspect_specific_sources"
            ? "The prompt references explicit sources/URLs, so those sources should be inspected directly."
            : heuristicDisposition === "search_web"
              ? "The prompt looks current or research-oriented, so external investigation should happen before answering."
              : undefined;
  if (!params.modelDisposition && heuristicDisposition) {
    return {
      disposition: heuristicDisposition,
      heuristicDisposition,
      heuristicRationale,
    };
  }
  if (!params.modelDisposition) {
    return {
      disposition: "answer_directly",
    };
  }
  if (!heuristicDisposition) {
    return { disposition: params.modelDisposition };
  }
  if (dispositionPriority(heuristicDisposition) > dispositionPriority(params.modelDisposition)) {
    return {
      disposition: heuristicDisposition,
      heuristicDisposition,
      heuristicRationale,
    };
  }
  return {
    disposition: params.modelDisposition,
    heuristicDisposition,
    heuristicRationale,
  };
}

function defaultPlannedStepsForDisposition(
  disposition: ResearchDisposition,
  prompt: string,
): string[] {
  switch (disposition) {
    case "read_document":
      return [
        "Find the primary document or PDF if it is not already provided.",
        "Inspect the PDF/document directly before relying on summaries.",
        "Read the sections needed to support the requested claims, especially methodology and results when relevant.",
      ];
    case "inspect_repo":
      return [
        "Inspect the relevant repository, files, and git state before answering.",
        "Base the answer on observed code instead of assumptions.",
      ];
    case "inspect_specific_sources":
      return [
        "Inspect the specific sources the user referenced before answering.",
        "Use additional sources only if they help verify or clarify the requested sources.",
      ];
    case "use_browser":
      return [
        "Use browser inspection for the relevant pages or flows.",
        "Only rely on plain fetch when rendering or state does not matter.",
      ];
    case "search_web":
      return [
        looksLikeCurrentInfoPrompt(prompt)
          ? "Search for current information before answering."
          : "Search for relevant sources before answering.",
        "Inspect the strongest sources instead of relying on a single result.",
      ];
    case "answer_directly":
    default:
      return [];
  }
}

function buildResearchExecutionPolicy(params: {
  prompt: string;
  disposition: ResearchDisposition;
  rationale: string;
  plannedSteps: string[];
}): string | null {
  if (params.disposition === "answer_directly") {
    return null;
  }

  const lines = [
    "Qypha research execution policy for this request:",
    `- Planned disposition: ${params.disposition}.`,
    `- Reason: ${params.rationale}.`,
    "- Choose the concrete tools and order dynamically, but satisfy this policy before giving a strong final answer.",
  ];

  switch (params.disposition) {
    case "read_document":
      lines.push(
        "- This request is document/paper centric. If a primary PDF or long document exists, inspect it directly before relying on summaries.",
      );
      lines.push(
        "- Use web_search to find the primary source, pdf to read it, and web_fetch or browser/download fallback when needed.",
      );
      lines.push(
        "- Do not describe the paper as read unless the primary document was actually inspected. If it could not be read, say so clearly.",
      );
      break;
    case "inspect_repo":
      lines.push(
        "- This request is repo/code centric. Inspect the relevant files, repo state, and tools before answering.",
      );
      lines.push("- Prefer observed code facts over assumptions.");
      break;
    case "inspect_specific_sources":
      lines.push(
        "- Inspect the exact sources or URLs implied by the user before answering from memory.",
      );
      break;
    case "use_browser":
      lines.push(
        "- Use browser inspection when rendering, state, login, or JS-heavy behavior matters.",
      );
      break;
    case "search_web":
      lines.push(
        "- Use web research before answering. Inspect multiple strong sources when the claim is important or current.",
      );
      break;
    default:
      break;
  }

  const steps = params.plannedSteps.filter((step) => step.trim().length > 0);
  if (steps.length > 0) {
    lines.push("- Suggested investigation steps:");
    for (const step of steps.slice(0, 6)) {
      lines.push(`  - ${step}`);
    }
  }

  return lines.join("\n");
}

function inferSourceKind(url: string, fallback?: unknown): string | undefined {
  const hinted = normalizeOptionalString(fallback);
  if (hinted) {
    return hinted;
  }
  const lower = url.trim().toLowerCase();
  if (!lower) {
    return undefined;
  }
  if (lower.endsWith(".pdf") || lower.includes("arxiv.org/pdf/")) {
    return "pdf";
  }
  if (lower.includes("github.com")) {
    return "github";
  }
  if (lower.includes("arxiv.org") || lower.includes("doi.org")) {
    return "paper";
  }
  if (lower.includes("docs.") || lower.includes("/docs/")) {
    return "docs";
  }
  if (lower.includes("news")) {
    return "news";
  }
  return "web";
}

function normalizeResearchSource(value: unknown): ResearchSource | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const url =
    normalizeOptionalString(record.url) ??
    normalizeOptionalString(record.link) ??
    normalizeOptionalString(record.href);
  if (!url) {
    return null;
  }
  const title =
    unwrapExternalContentText(normalizeOptionalString(record.title)) ??
    unwrapExternalContentText(normalizeOptionalString(record.name)) ??
    url;
  const snippet =
    unwrapExternalContentText(normalizeOptionalString(record.snippet)) ??
    unwrapExternalContentText(normalizeOptionalString(record.summary)) ??
    unwrapExternalContentText(normalizeOptionalString(record.description)) ??
    unwrapExternalContentText(normalizeOptionalString(record.content));
  return {
    title,
    url,
    ...(snippet ? { snippet } : {}),
    ...(inferSourceKind(url, record.source_kind ?? record.kind)
      ? {
          source_kind: inferSourceKind(url, record.source_kind ?? record.kind),
        }
      : {}),
    ...(coerceNumber(record.score) !== undefined ? { score: coerceNumber(record.score) } : {}),
  };
}

function normalizeResearchSourceScope(
  value: ResearchSourceScope | null | undefined,
): ResearchSourceScope | undefined {
  if (!value) {
    return undefined;
  }
  const allowed_domains = normalizeAllowedDomains(value.allowed_domains);
  const prioritized_domains = normalizeAllowedDomains(value.prioritized_domains);
  return {
    allowed_domains,
    prioritized_domains,
    allow_open_web: value.allow_open_web !== false,
    allow_connected_sources: value.allow_connected_sources === true,
  };
}

function hostMatchesAnyDomain(url: string, domains: string[]): boolean {
  if (domains.length === 0) {
    return true;
  }
  try {
    const hostname = new URL(url).hostname.trim().toLowerCase();
    return domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  } catch {
    return false;
  }
}

function domainPriority(url: string, domains: string[]): number {
  if (domains.length === 0) {
    return Number.MAX_SAFE_INTEGER;
  }
  try {
    const hostname = new URL(url).hostname.trim().toLowerCase();
    const index = domains.findIndex(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
    );
    return index === -1 ? Number.MAX_SAFE_INTEGER : index;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

function applyResearchSourceScope(
  sources: ResearchSource[],
  scope: ResearchSourceScope | undefined,
): ResearchSource[] {
  if (!scope) {
    return sources;
  }
  if (scope.allow_open_web === false && (scope.allowed_domains?.length ?? 0) === 0) {
    return [];
  }

  let next = sources;
  if ((scope.allowed_domains?.length ?? 0) > 0) {
    next = next.filter((source) => hostMatchesAnyDomain(source.url, scope.allowed_domains ?? []));
  }
  if ((scope.prioritized_domains?.length ?? 0) > 0) {
    next = [...next].sort((left, right) => {
      const leftPriority = domainPriority(left.url, scope.prioritized_domains ?? []);
      const rightPriority = domainPriority(right.url, scope.prioritized_domains ?? []);
      if (leftPriority !== rightPriority) {
        return leftPriority - rightPriority;
      }
      return (right.score ?? 0) - (left.score ?? 0);
    });
  }
  return next;
}

function classifyResearchSource(source: ResearchSource): SourceClassification {
  const hinted = source.source_kind?.trim().toLowerCase();
  switch (hinted) {
    case "paper":
    case "research_paper":
      return "paper";
    case "repo":
    case "repository":
      return "repo";
    case "news":
      return "news";
    case "summary":
    case "blog":
      return "summary";
    case "official_doc":
    case "official-doc":
    case "documentation":
    case "docs":
      return "official_doc";
    case "primary":
      return "primary";
    case "secondary":
      return "secondary";
    case "web":
      return "web";
    default:
      break;
  }

  const lowerUrl = source.url.trim().toLowerCase();
  if (
    lowerUrl.includes("arxiv.org") ||
    lowerUrl.endsWith(".pdf") ||
    lowerUrl.includes("/pdf/") ||
    lowerUrl.includes("doi.org")
  ) {
    return "paper";
  }
  if (lowerUrl.includes("github.com")) {
    return "repo";
  }
  if (
    lowerUrl.includes("/docs/") ||
    lowerUrl.includes("developer.") ||
    lowerUrl.includes("docs.")
  ) {
    return "official_doc";
  }
  if (lowerUrl.includes("/blog/") || lowerUrl.includes("medium.com")) {
    return "summary";
  }
  if (lowerUrl.includes("/news/")) {
    return "news";
  }
  return "web";
}

function extractMarkdownHeadings(markdown: string): string[] {
  return Array.from(
    new Set(
      Array.from(markdown.matchAll(/^#{1,6}\s+(.+)$/gm))
        .map((match) => match[1]?.trim())
        .filter((value): value is string => Boolean(value))
        .slice(0, 32),
    ),
  );
}

function createResearchActionLogEntry(params: {
  action: string;
  url?: string;
  session_id?: string;
  query?: string;
  note?: string;
}): ResearchActionLogEntry {
  return {
    action: params.action,
    at_ms: Date.now(),
    ...(params.url?.trim() ? { url: params.url.trim() } : {}),
    ...(params.session_id?.trim() ? { session_id: params.session_id.trim() } : {}),
    ...(params.query?.trim() ? { query: params.query.trim() } : {}),
    ...(params.note?.trim() ? { note: params.note.trim() } : {}),
  };
}

function buildConsultedSourceRecord(params: {
  source: ResearchSource;
  extractionMode: string;
  content: string;
  headings?: string[];
  pageRanges?: string[];
  findQueries?: string[];
  notes?: string;
}): ConsultedSourceRecord {
  return {
    source: params.source,
    classification: classifyResearchSource(params.source),
    extraction_mode: params.extractionMode.trim() || "unknown",
    accessed_at_ms: Date.now(),
    content_length_chars: params.content.trim().length,
    ...(params.pageRanges && params.pageRanges.length > 0 ? { page_ranges: params.pageRanges } : {}),
    ...(params.headings && params.headings.length > 0 ? { headings: params.headings } : {}),
    ...(params.findQueries && params.findQueries.length > 0
      ? { find_queries: Array.from(new Set(params.findQueries.map((value) => value.trim()).filter(Boolean))) }
      : {}),
    ...(params.notes?.trim() ? { notes: params.notes.trim() } : {}),
  };
}

function canonicalizeResearchUrl(rawUrl: string): string | null {
  try {
    const resolved = new URL(rawUrl.trim());
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
      return null;
    }
    resolved.hash = "";
    return resolved.toString();
  } catch {
    return null;
  }
}

function resolveResearchLinkUrl(rawHref: string, baseUrl: string): string | null {
  try {
    const resolved = new URL(rawHref.trim(), baseUrl);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
      return null;
    }
    resolved.hash = "";
    return resolved.toString();
  } catch {
    return null;
  }
}

function scoreResearchFollowUpLink(params: {
  source: ResearchSource;
  candidateUrl: string;
  label: string;
  query: string;
  pageTextHint: string;
}): { score: number; rationale: string } {
  const lowerUrl = params.candidateUrl.toLowerCase();
  const lowerLabel = params.label.trim().toLowerCase();
  const lowerQuery = params.query.trim().toLowerCase();
  const lowerPageHint = params.pageTextHint.trim().toLowerCase();
  const reasons: string[] = [];
  let score = 0;

  const addScore = (value: number, reason: string) => {
    score += value;
    reasons.push(reason);
  };

  if (
    lowerUrl.endsWith(".pdf") ||
    lowerUrl.includes("/pdf/") ||
    lowerUrl.includes("format=pdf") ||
    lowerUrl.includes("download=pdf")
  ) {
    addScore(60, "pdf_link");
  }
  if (lowerUrl.includes("arxiv.org/pdf/")) {
    addScore(20, "arxiv_pdf");
  }
  if (lowerUrl.includes("doi.org")) {
    addScore(12, "doi");
  }

  const appendixPattern = /\b(appendix|appendices|supplement|supplementary|supplemental|supp)\b/i;
  const fullTextPattern =
    /\b(full text|full paper|paper pdf|download pdf|download paper|manuscript|preprint|accepted manuscript|camera ready|final paper)\b/i;
  const documentPattern =
    /\b(pdf|paper|article|publication|technical report|whitepaper|report|appendix|supplementary)\b/i;
  const negativePattern =
    /\b(blog|news|press|video|slides|poster|tweet|x\.com|twitter|reddit|issue|pull request|commit|code|github)\b/i;

  if (appendixPattern.test(params.label) || appendixPattern.test(params.candidateUrl)) {
    addScore(40, "appendix_or_supplement");
  }
  if (fullTextPattern.test(params.label) || fullTextPattern.test(params.candidateUrl)) {
    addScore(35, "full_text_signal");
  }
  if (documentPattern.test(params.label) || documentPattern.test(params.candidateUrl)) {
    addScore(18, "document_signal");
  }
  if (negativePattern.test(params.label) || negativePattern.test(params.candidateUrl)) {
    addScore(-55, "non_document_signal");
  }

  const candidateClassification = classifyResearchSource({
    title: params.label || params.candidateUrl,
    url: params.candidateUrl,
    source_kind: inferSourceKind(params.candidateUrl, undefined),
  });
  if (candidateClassification === "paper") {
    addScore(24, "paper_candidate");
  } else if (candidateClassification === "official_doc") {
    addScore(16, "official_document_candidate");
  }

  const sourceClassification = classifyResearchSource(params.source);
  if (
    (sourceClassification === "summary" ||
      sourceClassification === "web" ||
      sourceClassification === "news") &&
    (candidateClassification === "paper" || candidateClassification === "official_doc")
  ) {
    addScore(18, "stronger_primary_source");
  }

  if (looksLikePaperResearchPrompt(lowerQuery)) {
    if (candidateClassification === "paper") {
      addScore(20, "paper_query_alignment");
    }
    if (appendixPattern.test(lowerQuery) && appendixPattern.test(params.label)) {
      addScore(14, "appendix_query_alignment");
    }
  }

  if (
    lowerPageHint.includes("appendix") ||
    lowerPageHint.includes("supplementary") ||
    lowerPageHint.includes("full text") ||
    lowerPageHint.includes("download pdf")
  ) {
    addScore(8, "page_signal_alignment");
  }

  return {
    score,
    rationale: reasons.join(", ") || "weak_signal",
  };
}

function extractResearchFollowUpCandidates(params: {
  markdown: string;
  source: ResearchSource;
  query: string;
  pageTextHint: string;
}): ResearchFollowUpCandidate[] {
  const markdown = params.markdown.trim();
  if (!markdown) {
    return [];
  }

  const baseUrl = params.source.url;
  const baseCanonical = canonicalizeResearchUrl(baseUrl);
  const ir = markdownToIR(markdown, {
    autolink: true,
    linkify: true,
  });
  const candidates: ResearchFollowUpCandidate[] = [];
  const seen = new Set<string>();

  for (const link of ir.links) {
    const rawHref = link.href?.trim();
    if (!rawHref) {
      continue;
    }
    const resolvedUrl = resolveResearchLinkUrl(rawHref, baseUrl);
    if (!resolvedUrl) {
      continue;
    }
    if (baseCanonical && resolvedUrl === baseCanonical) {
      continue;
    }
    if (seen.has(resolvedUrl)) {
      continue;
    }
    seen.add(resolvedUrl);

    const label = ir.text.slice(link.start, link.end).trim() || resolvedUrl;
    const scored = scoreResearchFollowUpLink({
      source: params.source,
      candidateUrl: resolvedUrl,
      label,
      query: params.query,
      pageTextHint: params.pageTextHint,
    });
    if (scored.score < 30) {
      continue;
    }
    candidates.push({
      source: {
        title: label,
        url: resolvedUrl,
        source_kind: inferSourceKind(resolvedUrl, undefined),
      },
      label,
      score: scored.score,
      rationale: scored.rationale,
    });
  }

  return candidates.sort((left, right) => right.score - left.score).slice(0, 6);
}

function shouldAttemptLinkedDocumentFollowUp(params: {
  source: ResearchSource;
  query: string;
  linkCandidates: ResearchFollowUpCandidate[];
  extractedText: string;
}): boolean {
  if (params.linkCandidates.length === 0) {
    return false;
  }
  const topCandidate = params.linkCandidates[0];
  if (!topCandidate) {
    return false;
  }
  if (topCandidate.score >= 70) {
    return true;
  }

  const lowerText = params.extractedText.trim().toLowerCase();
  if (
    looksLikePaperResearchPrompt(params.query) ||
    classifyResearchSource(params.source) === "paper" ||
    lowerText.includes("supplementary") ||
    lowerText.includes("appendix") ||
    lowerText.includes("full text") ||
    lowerText.includes("download pdf")
  ) {
    return topCandidate.score >= 45;
  }

  return false;
}

function inferLinkedDocumentFollowUpBudget(query: string): number {
  const lowerQuery = query.trim().toLowerCase();
  if (
    lowerQuery.includes("appendix") ||
    lowerQuery.includes("supplementary") ||
    lowerQuery.includes("supplemental")
  ) {
    return 2;
  }
  return 1;
}

function shouldAppendLinkedDocument(params: {
  query: string;
  candidate: ResearchFollowUpCandidate;
}): boolean {
  const combined = `${params.query} ${params.candidate.label} ${params.candidate.source.url}`.toLowerCase();
  return /\b(appendix|appendices|supplement|supplementary|supplemental)\b/.test(combined);
}

function shouldPreferLinkedDocument(params: {
  currentSource: ResearchSource;
  currentText: string;
  query: string;
  candidate: ResearchFollowUpCandidate;
  followUpText: string;
}): boolean {
  const currentClassification = classifyResearchSource(params.currentSource);
  const followUpClassification = classifyResearchSource(params.candidate.source);
  const currentHits = countQueryTokenHits(params.currentText, params.query);
  const followUpHits = countQueryTokenHits(params.followUpText, params.query);

  if (
    (currentClassification === "summary" ||
      currentClassification === "web" ||
      currentClassification === "news") &&
    (followUpClassification === "paper" || followUpClassification === "official_doc")
  ) {
    return true;
  }
  if (followUpHits > currentHits) {
    return true;
  }
  if (
    followUpClassification === "paper" &&
    params.followUpText.trim().length > params.currentText.trim().length * 1.2
  ) {
    return true;
  }
  return false;
}

function combineInspectionTexts(params: {
  baseText: string;
  linkedTitle: string;
  linkedText: string;
  maxChars: number;
}): { text: string; truncated: boolean } {
  const sections = [
    params.baseText.trim(),
    `## Linked follow-up document: ${params.linkedTitle.trim() || "Linked document"}\n\n${params.linkedText.trim()}`,
  ].filter(Boolean);
  const combined = sections.join("\n\n");
  if (combined.length <= params.maxChars) {
    return { text: combined, truncated: false };
  }
  const suffix = "\n\n[linked follow-up truncated to inspection budget]";
  const budget = Math.max(0, params.maxChars - suffix.length);
  return {
    text: `${combined.slice(0, budget).trimEnd()}${suffix}`,
    truncated: true,
  };
}

async function fetchResearchInspectionContent(params: {
  fetchTool: EmbeddedFetchTool;
  source: ResearchSource;
  query: string;
  maxChars: number;
}): Promise<ResearchFetchedInspection> {
  const rawResult = await params.fetchTool.execute("qypha-research-inspect", {
    url: params.source.url,
    extractMode: "markdown",
    maxChars: params.maxChars,
  });
  const details =
    rawResult.details &&
    typeof rawResult.details === "object" &&
    !Array.isArray(rawResult.details)
      ? (rawResult.details as Record<string, unknown>)
      : {};
  const markdown = unwrapExternalContentText(normalizeOptionalString(details.text)) ?? "";
  const ir = markdownToIR(markdown, {
    autolink: true,
    linkify: true,
  });
  const plainText = ir.text.trim() || markdown.trim();
  const extractor = normalizeOptionalString(details.extractor) ?? "web_fetch_markdown";
  const warning = normalizeOptionalString(details.warning);
  const contentType = normalizeOptionalString(details.contentType);
  const notes = [extractor, warning].filter(Boolean).join(" | ");
  return {
    displayText: markdown.trim() || plainText,
    plainText,
    headings: extractMarkdownHeadings(markdown),
    extractor,
    warning,
    contentType,
    notes,
    linkCandidates: extractResearchFollowUpCandidates({
      markdown,
      source: params.source,
      query: params.query,
      pageTextHint: plainText.slice(0, 8_000),
    }),
  };
}

function resolveOpenAIGpt54ForwardCompatModel(params: {
  modelId: string;
  registry: EmbeddedModelRegistry;
  metadata?: Record<string, string>;
}): RuntimeModel | undefined {
  const trimmed = params.modelId.trim();
  const lower = trimmed.toLowerCase();
  let templateIds: readonly string[];
  let patch: Partial<RuntimeModel>;
  if (lower === OPENAI_GPT_54_MODEL_ID) {
    templateIds = OPENAI_GPT_54_TEMPLATE_MODEL_IDS;
    patch = {
      api: "openai-responses",
      provider: "openai",
      baseUrl: providerBaseUrl("openai", params.metadata),
      reasoning: true,
      input: ["text", "image"],
      contextWindow: OPENAI_GPT_54_CONTEXT_TOKENS,
      maxTokens: OPENAI_GPT_54_MAX_TOKENS,
    };
  } else if (lower === OPENAI_GPT_54_PRO_MODEL_ID) {
    templateIds = OPENAI_GPT_54_PRO_TEMPLATE_MODEL_IDS;
    patch = {
      api: "openai-responses",
      provider: "openai",
      baseUrl: providerBaseUrl("openai", params.metadata),
      reasoning: true,
      input: ["text", "image"],
      contextWindow: OPENAI_GPT_54_CONTEXT_TOKENS,
      maxTokens: OPENAI_GPT_54_MAX_TOKENS,
    };
  } else if (lower === OPENAI_GPT_54_MINI_MODEL_ID) {
    templateIds = OPENAI_GPT_54_MINI_TEMPLATE_MODEL_IDS;
    patch = {
      api: "openai-responses",
      provider: "openai",
      baseUrl: providerBaseUrl("openai", params.metadata),
      reasoning: true,
      input: ["text", "image"],
    };
  } else if (lower === OPENAI_GPT_54_NANO_MODEL_ID) {
    templateIds = OPENAI_GPT_54_NANO_TEMPLATE_MODEL_IDS;
    patch = {
      api: "openai-responses",
      provider: "openai",
      baseUrl: providerBaseUrl("openai", params.metadata),
      reasoning: true,
      input: ["text", "image"],
    };
  } else {
    return undefined;
  }

  return (cloneFirstTemplateModel({
    providerId: "openai",
    modelId: trimmed,
    templateIds,
    ctx: {
      provider: "openai",
      modelId: trimmed,
      modelRegistry: params.registry as never,
    },
    patch,
  }) ??
    normalizeModelCompat({
      id: trimmed,
      name: trimmed,
      ...patch,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: patch.contextWindow ?? DEFAULT_CONTEXT_TOKENS,
      maxTokens: patch.maxTokens ?? DEFAULT_CONTEXT_TOKENS,
    } as RuntimeModel)) as RuntimeModel;
}

function resolveAnthropic46ForwardCompatModel(params: {
  modelId: string;
  registry: EmbeddedModelRegistry;
  dashModelId: string;
  dotModelId: string;
  dashTemplateId: string;
  dotTemplateId: string;
  fallbackTemplateIds: readonly string[];
}) {
  const trimmed = params.modelId.trim();
  const lower = trimmed.toLowerCase();
  const is46Model =
    lower === params.dashModelId ||
    lower === params.dotModelId ||
    lower.startsWith(`${params.dashModelId}-`) ||
    lower.startsWith(`${params.dotModelId}-`);
  if (!is46Model) {
    return undefined;
  }

  const templateIds: string[] = [];
  if (lower.startsWith(params.dashModelId)) {
    templateIds.push(lower.replace(params.dashModelId, params.dashTemplateId));
  }
  if (lower.startsWith(params.dotModelId)) {
    templateIds.push(lower.replace(params.dotModelId, params.dotTemplateId));
  }
  templateIds.push(...params.fallbackTemplateIds);

  return cloneFirstTemplateModel({
    providerId: "anthropic",
    modelId: trimmed,
    templateIds,
    ctx: {
      provider: "anthropic",
      modelId: trimmed,
      modelRegistry: params.registry as never,
    },
  }) as RuntimeModel | undefined;
}

function resolveAnthropicForwardCompatModel(params: {
  modelId: string;
  registry: EmbeddedModelRegistry;
}) {
  return (
    resolveAnthropic46ForwardCompatModel({
      modelId: params.modelId,
      registry: params.registry,
      dashModelId: ANTHROPIC_OPUS_46_MODEL_ID,
      dotModelId: ANTHROPIC_OPUS_46_DOT_MODEL_ID,
      dashTemplateId: "claude-opus-4-5",
      dotTemplateId: "claude-opus-4.5",
      fallbackTemplateIds: ANTHROPIC_OPUS_TEMPLATE_MODEL_IDS,
    }) ??
    resolveAnthropic46ForwardCompatModel({
      modelId: params.modelId,
      registry: params.registry,
      dashModelId: ANTHROPIC_SONNET_46_MODEL_ID,
      dotModelId: ANTHROPIC_SONNET_46_DOT_MODEL_ID,
      dashTemplateId: "claude-sonnet-4-5",
      dotTemplateId: "claude-sonnet-4.5",
      fallbackTemplateIds: ANTHROPIC_SONNET_TEMPLATE_MODEL_IDS,
    })
  );
}

function openAIStreamFn(base: StreamFn): StreamFn {
  return createOpenAIAttributionHeadersWrapper(createOpenAIDefaultTransportWrapper(base));
}

const PROVIDERS: Record<EmbeddedProviderAdapter["id"], EmbeddedProviderAdapter> = {
  ollama: {
    id: "ollama",
    resolveModel(modelId, metadata) {
      return buildRuntimeModel("ollama", modelId, metadata);
    },
    missingAuthMessage: () => "Ollama runtime is not reachable.",
  },
  openai: {
    id: "openai",
    resolveModel(modelId, metadata) {
      const registry = createModelRegistry("openai", modelId, metadata);
      return (
        resolveOpenAIGpt54ForwardCompatModel({ modelId, registry, metadata }) ??
        buildRuntimeModel("openai", modelId, metadata)
      );
    },
    wrapStreamFn: (streamFn) => openAIStreamFn(streamFn),
    missingAuthMessage: () =>
      "No API key resolved for provider 'openai'. Set OPENAI_API_KEY for embedded runtime access.",
  },
  anthropic: {
    id: "anthropic",
    resolveModel(modelId, metadata) {
      const registry = createModelRegistry("anthropic", modelId, metadata);
      return (
        resolveAnthropicForwardCompatModel({ modelId, registry }) ??
        buildRuntimeModel("anthropic", modelId, metadata)
      );
    },
    missingAuthMessage: () =>
      "No API key resolved for provider 'anthropic'. Set ANTHROPIC_API_KEY or ANTHROPIC_OAUTH_TOKEN.",
  },
  google: {
    id: "google",
    resolveModel(modelId, metadata) {
      const registry = createModelRegistry("google", modelId, metadata);
      return (
        resolveGoogle31ForwardCompatModel({
          providerId: "google",
          ctx: {
            provider: "google",
            modelId,
            modelRegistry: registry as never,
          },
        }) as RuntimeModel | undefined ?? buildRuntimeModel("google", modelId, metadata)
      );
    },
    wrapStreamFn: (streamFn) => createGoogleThinkingPayloadWrapper(streamFn),
    missingAuthMessage: () =>
      "No API key resolved for provider 'google'. Set GEMINI_API_KEY or GOOGLE_API_KEY.",
  },
};

function resolveApiKey(provider: EmbeddedProviderAdapter["id"]): string {
  switch (provider) {
    case "ollama":
      return process.env.OLLAMA_API_KEY?.trim() || "ollama-local";
    case "openai":
      return process.env.OPENAI_API_KEY?.trim() || "";
    case "anthropic":
      return (
        process.env.ANTHROPIC_API_KEY?.trim() ||
        process.env.ANTHROPIC_OAUTH_TOKEN?.trim() ||
        process.env.CLAUDE_API_KEY?.trim() ||
        ""
      );
    case "google":
      return process.env.GEMINI_API_KEY?.trim() || process.env.GOOGLE_API_KEY?.trim() || "";
  }
}

function buildSimpleMessages(payload: ProviderGenerateRequest) {
  const now = Date.now();
  const messages: Array<{
    role: "system" | "user" | "assistant";
    content: string;
    timestamp: number;
  }> = [];
  const systemPrompt = payload.system_prompt?.trim();
  if (systemPrompt) {
    messages.push({
      role: "system",
      content: systemPrompt,
      timestamp: now,
    });
  }
  for (const entry of payload.messages ?? []) {
    const role =
      entry.role === "assistant" ? "assistant" : entry.role === "system" ? "system" : "user";
    const content = entry.content.trim();
    if (!content) {
      continue;
    }
    messages.push({
      role,
      content,
      timestamp: now,
    });
  }
  return messages;
}

function extractAssistantText(message: AssistantMessage | undefined): string {
  const content = message?.content;
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .filter((block) => block?.type === "text")
    .map((block) => block.text?.trim() ?? "")
    .filter(Boolean)
    .join("\n")
    .trim();
}

function resolveMetadataString(
  metadata: Record<string, string> | undefined,
  key: string,
): string | undefined {
  const value = metadata?.[key]?.trim();
  return value ? value : undefined;
}

function resolveWorkspaceDir(
  metadata: Record<string, string> | undefined,
  actorId?: string,
): string {
  const metadataWorkspaceDir = resolveMetadataString(metadata, "workspace_dir");
  if (metadataWorkspaceDir) {
    return path.resolve(metadataWorkspaceDir);
  }
  const actor = resolveEmbeddedActorContext({
    actorId,
    metadata,
  });
  return path.resolve(resolveEmbeddedStateRootDir(), "agents", actor.agentId, "workspace");
}

function sanitizeIdentifier(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || "default";
}

function browserProfileForSession(sessionId: string): string {
  return `qypha-${sanitizeIdentifier(sessionId)}`.slice(0, 64);
}

function normalizeSessionId(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("session_id is required");
  }
  return trimmed;
}

function normalizeAllowedDomains(domains: string[] | undefined): string[] {
  return Array.from(
    new Set((domains ?? []).map((entry) => entry.trim().toLowerCase()).filter(Boolean)),
  );
}

function assertUrlAllowed(url: string, allowedDomains: string[]) {
  if (allowedDomains.length === 0) {
    return;
  }
  const parsed = new URL(url);
  const hostname = parsed.hostname.trim().toLowerCase();
  const allowed = allowedDomains.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );
  if (!allowed) {
    throw new Error(
      `URL host "${hostname}" is outside the allowed browser domains for this session.`,
    );
  }
}

function extractPayloadText(payloads: Array<{ text?: string }> | undefined): string {
  return (payloads ?? [])
    .map((entry) => entry.text?.trim())
    .filter((value): value is string => Boolean(value))
    .join("\n\n")
    .trim();
}

async function generateWithProvider(payload: ProviderGenerateRequest) {
  const provider = normalizeProviderId(payload.provider);
  const modelId = payload.model_id.trim();
  if (!modelId) {
    throw new Error("model_id is required");
  }

  const agentDir = payload.metadata?.agent_dir?.trim();
  if (agentDir) {
    fs.mkdirSync(agentDir, { recursive: true });
  }

  const adapter = PROVIDERS[provider];
  const model = adapter.resolveModel(modelId, payload.metadata);
  const apiKey = resolveApiKey(provider);
  if (!apiKey && provider !== "ollama") {
    throw new Error(adapter.missingAuthMessage());
  }

  const streamFn = adapter.wrapStreamFn ? adapter.wrapStreamFn(streamSimple) : streamSimple;
  const stream = streamFn(
    model,
    { messages: buildSimpleMessages(payload) } as never,
    {
      apiKey,
      maxTokens: Math.min(model.maxTokens ?? DEFAULT_CONTEXT_TOKENS, 8192),
    } as never,
  ) as AsyncIterable<{ type: string; message?: AssistantMessage }>;

  let done: AssistantMessage | undefined;
  for await (const event of stream) {
    if (event.type === "done") {
      done = event.message;
    }
  }

  const outputText = extractAssistantText(done);
  if (!outputText) {
    throw new Error(`Model ${provider}/${modelId} returned an empty assistant response`);
  }

  return {
    ok: true as const,
    model_id: model.id,
    output_text: outputText,
    finish_reason: done?.stopReason,
  };
}

async function runProviderHealthcheck(_payload: ProviderHealthcheckRequest) {
  await loadOwnerManagedCapabilityBaseConfig();
  return {
    ok: true as const,
  };
}

async function runProviderListModels(payload: ProviderListModelsRequest) {
  const provider = normalizeProviderId(payload.provider);
  if (provider === "ollama") {
    const { models } = await fetchOllamaModels(providerBaseUrl(provider, payload.metadata));
    const catalog = models
      .map((model) => buildOllamaModelDefinition(model.name))
      .map((model) =>
        toProviderCatalogEntry(provider, {
          id: model.id,
          name: model.name ?? model.id,
          input: Array.isArray(model.input)
            ? model.input.filter(
                (entry): entry is "text" | "image" => entry === "text" || entry === "image",
              )
            : undefined,
        }),
      );
    return {
      ok: true as const,
      catalog,
    };
  }

  const catalog = staticTemplateModels(provider, payload.metadata).map((model) =>
    toProviderCatalogEntry(provider, model, {
      local: false,
      supportsTools: true,
    }),
  );
  return {
    ok: true as const,
    catalog,
  };
}

function resolvePathFromWorkspace(
  inputPath: string,
  metadata?: Record<string, string>,
): string {
  const trimmed = inputPath.trim();
  if (!trimmed) {
    throw new Error("path is required");
  }
  if (path.isAbsolute(trimmed)) {
    return path.resolve(trimmed);
  }
  return path.resolve(resolveWorkspaceDir(metadata), trimmed);
}

function extractToolText(result: {
  content?: AgentToolResult<unknown>["content"];
  details?: unknown;
}): string {
  const details =
    result.details && typeof result.details === "object" && !Array.isArray(result.details)
      ? (result.details as Record<string, unknown>)
      : {};
  if (typeof details.structuredContent === "string") {
    return details.structuredContent;
  }
  return (result.content ?? [])
    .filter((entry) => entry?.type === "text")
    .map((entry) => entry.text?.trim() ?? "")
    .filter(Boolean)
    .join("\n")
    .trim();
}

function ensureBundledCapabilityToolSucceeded(
  toolName: string,
  result: {
    content?: AgentToolResult<unknown>["content"];
    details?: unknown;
  },
) {
  const details =
    result.details && typeof result.details === "object" && !Array.isArray(result.details)
      ? (result.details as Record<string, unknown>)
      : {};
  const status = normalizeOptionalString(details.status)?.toLowerCase();
  if (status === "error") {
    throw new Error(extractToolText(result) || `Bundled capability "${toolName}" failed`);
  }
}

const BUNDLED_CAPABILITY_DIRECTORY_HINTS = new Set([
  "cwd",
  "dir",
  "directory",
  "root",
  "workspace",
  "workspace_dir",
  "workspaceDir",
]);

const BUNDLED_CAPABILITY_PATH_HINTS = new Set([
  ...BUNDLED_CAPABILITY_DIRECTORY_HINTS,
  "destination",
  "file",
  "files",
  "from",
  "path",
  "paths",
  "to",
]);

function normalizeBundledCapabilityRootCandidate(
  rawPath: string,
  mode: "auto" | "directory",
): string | null {
  const trimmed = rawPath.trim();
  if (!trimmed || !path.isAbsolute(trimmed)) {
    return null;
  }
  const resolved = path.resolve(trimmed);
  if (mode === "directory") {
    return resolved;
  }
  try {
    const stats = fs.statSync(resolved);
    return stats.isDirectory() ? resolved : path.dirname(resolved);
  } catch {
    return path.dirname(resolved);
  }
}

function collectBundledCapabilityAllowedDirs(
  value: unknown,
  keyHint?: string,
): string[] {
  const normalizedHint = keyHint?.trim();
  if (typeof value === "string") {
    if (!normalizedHint || !BUNDLED_CAPABILITY_PATH_HINTS.has(normalizedHint)) {
      return [];
    }
    const candidate = normalizeBundledCapabilityRootCandidate(
      value,
      BUNDLED_CAPABILITY_DIRECTORY_HINTS.has(normalizedHint) ? "directory" : "auto",
    );
    return candidate ? [candidate] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry) => collectBundledCapabilityAllowedDirs(entry, normalizedHint));
  }
  if (!isRecord(value)) {
    return [];
  }
  return Object.entries(value).flatMap(([entryKey, entryValue]) =>
    collectBundledCapabilityAllowedDirs(entryValue, entryKey),
  );
}

async function normalizeBundledCapabilityAllowedDirs(
  workspaceDir: string,
  extraAllowedDirs: Iterable<string> = [],
): Promise<string[]> {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const rawCandidate of [workspaceDir, ...Array.from(extraAllowedDirs)]) {
    const trimmed = rawCandidate.trim();
    if (!trimmed) {
      continue;
    }
    const resolved = path.resolve(trimmed);
    const candidates = [resolved];
    try {
      const canonical = await fsp.realpath(resolved);
      if (canonical !== resolved) {
        candidates.push(canonical);
      }
    } catch {
      // Keep unresolved paths when a directory will be created later.
    }
    for (const candidate of candidates) {
      if (seen.has(candidate)) {
        continue;
      }
      seen.add(candidate);
      normalized.push(candidate);
    }
  }
  return normalized.length > 0 ? normalized : [path.resolve(workspaceDir)];
}

async function invokeBundledCapabilityTool(
  metadata: Record<string, string> | undefined,
  toolName: string,
  args: Record<string, unknown>,
) {
  const state = await ensureBundleMcpCapabilityState(metadata, {
    extraAllowedDirs: collectBundledCapabilityAllowedDirs(args),
  });
  const capability = state.capabilities.get(buildMcpCapabilityId(toolName));
  if (!capability) {
    throw new Error(`Bundled capability "${toolName}" is unavailable`);
  }
  const result = await capability.tool.execute(`qypha-${toolName}`, args);
  ensureBundledCapabilityToolSucceeded(toolName, result);
  return result;
}

type ParsedGitStatus = {
  root: string;
  vcs?: string;
  branch?: string;
  dirty: boolean;
  changed_files: string[];
};

async function inspectRepoStatus(root: string): Promise<ParsedGitStatus> {
  const normalizedRoot = path.resolve(root);
  let gitCheck;
  try {
    gitCheck = await runCommandWithTimeout(["git", "-C", normalizedRoot, "rev-parse", "--git-dir"], {
      timeoutMs: 10_000,
    });
  } catch {
    return {
      root: normalizedRoot,
      dirty: false,
      changed_files: [],
    };
  }

  if (gitCheck.code !== 0 || gitCheck.killed) {
    return {
      root: normalizedRoot,
      dirty: false,
      changed_files: [],
    };
  }

  const branchResult = await runCommandWithTimeout(
    ["git", "-C", normalizedRoot, "branch", "--show-current"],
    { timeoutMs: 10_000 },
  ).catch(() => null);
  const statusResult = await runCommandWithTimeout(
    ["git", "-C", normalizedRoot, "status", "--porcelain=v1"],
    { timeoutMs: 15_000 },
  );

  const changedFiles = statusResult.stdout
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean)
    .map((line) => {
      const payload = line.slice(3).trim();
      const renamed = payload.includes(" -> ") ? payload.split(" -> ").at(-1) ?? payload : payload;
      return path.resolve(normalizedRoot, renamed);
    });

  return {
    root: normalizedRoot,
    vcs: "git",
    branch: branchResult?.code === 0 ? branchResult.stdout.trim() || undefined : undefined,
    dirty: changedFiles.length > 0,
    changed_files: changedFiles,
  };
}

function flattenRepoTreeNodes(params: {
  root: string;
  nodes: RepoTreeNode[];
  depth?: number;
}): RepoTreeEntry[] {
  const entries: RepoTreeEntry[] = [];
  const visit = (node: RepoTreeNode, parentPath: string, level: number) => {
    const name = typeof node.name === "string" ? node.name.trim() : "";
    const kind = typeof node.type === "string" ? node.type.trim() : "";
    if (!name || !kind) {
      return;
    }
    const fullPath = path.resolve(parentPath, name);
    entries.push({
      path: fullPath,
      kind,
    });
    if (params.depth !== undefined && level >= params.depth) {
      return;
    }
    const children = Array.isArray(node.children) ? node.children : [];
    for (const child of children) {
      visit(child, fullPath, level + 1);
    }
  };

  for (const node of params.nodes) {
    visit(node, params.root, 1);
  }
  return entries;
}

async function runRepoOverview(payload: RepoOverviewRequest) {
  return {
    ok: true as const,
    ...(await inspectRepoStatus(resolvePathFromWorkspace(payload.root, payload.metadata))),
  };
}

async function runRepoTree(payload: RepoTreeRequest) {
  const root = resolvePathFromWorkspace(payload.root, payload.metadata);
  const result = await invokeBundledCapabilityTool(payload.metadata, "directory_tree", {
    path: root,
    excludePatterns: ["node_modules/**", ".git/**", "dist/**"],
  });
  const treeText = extractToolText(result);
  const parsed = JSON.parse(treeText) as unknown;
  const nodes = Array.isArray(parsed) ? (parsed as RepoTreeNode[]) : [];
  return {
    ok: true as const,
    root,
    entries: flattenRepoTreeNodes({
      root,
      nodes,
      depth:
        typeof payload.depth === "number" && Number.isFinite(payload.depth)
          ? Math.max(0, Math.floor(payload.depth))
          : undefined,
    }),
  };
}

async function runRepoGrep(payload: RepoSearchRequest) {
  const root = resolvePathFromWorkspace(payload.root, payload.metadata);
  const pattern = payload.pattern.trim();
  if (!pattern) {
    throw new Error("pattern is required");
  }
  const limit =
    typeof payload.limit === "number" && Number.isFinite(payload.limit)
      ? Math.max(1, Math.floor(payload.limit))
      : 20;

  let rgResult;
  try {
    rgResult = await runCommandWithTimeout(
      [
        "rg",
        "--json",
        "--line-number",
        "--color",
        "never",
        "--max-count",
        String(limit),
        pattern,
        root,
      ],
      { timeoutMs: 30_000 },
    );
  } catch {
    rgResult = null;
  }

  const matches: RepoSearchMatch[] = [];
  if (rgResult && rgResult.code === 0) {
    for (const line of rgResult.stdout.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      try {
        const parsed = JSON.parse(trimmed) as {
          type?: string;
          data?: {
            path?: { text?: string };
            lines?: { text?: string };
            line_number?: number;
          };
        };
        if (parsed.type !== "match" || !parsed.data?.path?.text || !parsed.data?.line_number) {
          continue;
        }
        matches.push({
          path: parsed.data.path.text,
          line_number: parsed.data.line_number,
          line_text: parsed.data.lines?.text?.trimEnd() ?? "",
        });
      } catch {
        // ignore malformed ripgrep rows
      }
    }
  } else {
    const grepResult = await runCommandWithTimeout(
      ["grep", "-RIn", "--exclude-dir=.git", "--exclude-dir=node_modules", pattern, root],
      { timeoutMs: 30_000 },
    ).catch(() => null);
    for (const line of grepResult?.stdout.split(/\r?\n/) ?? []) {
      const match = /^(.*?):(\d+):(.*)$/.exec(line);
      if (!match) {
        continue;
      }
      const [, filePath, lineNumber, lineText] = match;
      matches.push({
        path: filePath,
        line_number: Number.parseInt(lineNumber, 10),
        line_text: lineText,
      });
      if (matches.length >= limit) {
        break;
      }
    }
  }

  return {
    ok: true as const,
    root,
    repo_matches: matches.slice(0, limit),
  };
}

async function runRepoReadFile(payload: RepoReadFileRequest) {
  const filePath = resolvePathFromWorkspace(payload.path, payload.metadata);
  const result = await invokeBundledCapabilityTool(payload.metadata, "read_text_file", {
    path: filePath,
  });
  const content = extractToolText(result);
  return {
    ok: true as const,
    path: filePath,
    file_content: content,
  };
}

async function runRepoGitLog(payload: RepoGitLogRequest) {
  const root = resolvePathFromWorkspace(payload.root, payload.metadata);
  const limit =
    typeof payload.limit === "number" && Number.isFinite(payload.limit)
      ? Math.max(1, Math.floor(payload.limit))
      : 20;
  const check = await inspectRepoStatus(root);
  if (check.vcs !== "git") {
    return {
      ok: true as const,
      root,
      commits: [],
    };
  }

  const result = await runCommandWithTimeout(
    ["git", "-C", root, "log", `-n${limit}`, "--format=%H%x1f%s"],
    { timeoutMs: 20_000 },
  );
  const commits: RepoGitCommitEntry[] = [];
  for (const line of result.stdout.split(/\r?\n/)) {
    const [commitId, summary] = line.split("\u001f", 2);
    if (!commitId?.trim()) {
      continue;
    }
    commits.push({
      commit_id: commitId.trim(),
      summary: summary?.trim() ?? "",
    });
  }
  return {
    ok: true as const,
    root,
    commits,
  };
}

async function runRepoRemoteInspect(payload: RepoRemoteInspectRequest) {
  const url = payload.url.trim();
  if (!url) {
    throw new Error("url is required");
  }
  const args = ["git", "ls-remote", "--heads", "--tags", url];
  if (payload.reference?.trim()) {
    args.push(payload.reference.trim());
  }
  const result = await runCommandWithTimeout(args, { timeoutMs: 30_000 }).catch(() => null);
  const refs =
    result?.code === 0
      ? result.stdout
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => line.split(/\s+/, 2)[1] ?? "")
          .filter(Boolean)
      : [];
  const summary =
    refs.length > 0
      ? `Remote repository responded with ${refs.length} refs.`
      : result?.stderr.trim() || "Remote repository could not be inspected in depth.";
  return {
    ok: true as const,
    url,
    summary,
    candidate_files: [],
  };
}

function hashMemoryContent(content: string): string {
  return createHash("sha256").update(content).digest("hex").slice(0, 24);
}

function countTextLines(text: string): number {
  if (!text) {
    return 0;
  }
  return text.replace(/\r\n/g, "\n").split("\n").length;
}

function sanitizeMemoryPathSegment(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function normalizeMemoryRelativePath(raw: string): string {
  const normalized = raw.replace(/\\/g, "/").trim();
  if (!normalized) {
    return "MEMORY.md";
  }
  if (/^memory\.md$/i.test(normalized)) {
    return "MEMORY.md";
  }
  if (/^memory\/.+\.md$/i.test(normalized)) {
    const segments = normalized
      .split("/")
      .map((segment) => sanitizeMemoryPathSegment(segment.replace(/\.md$/i, "")))
      .filter(Boolean);
    if (segments.length === 0 || segments[0] !== "memory") {
      return "MEMORY.md";
    }
    return `${segments.join("/")}.md`;
  }
  return "MEMORY.md";
}

function resolveMemoryScopeRelativePath(scope: string): string {
  const trimmed = scope.trim();
  if (!trimmed) {
    return "MEMORY.md";
  }
  const lower = trimmed.toLowerCase();
  if (
    lower === "memory" ||
    lower === "main" ||
    lower === "default" ||
    lower === "root" ||
    lower === "memory-root" ||
    lower === "memory.md"
  ) {
    return "MEMORY.md";
  }
  if (lower.startsWith("memory/") || lower.endsWith(".md")) {
    return normalizeMemoryRelativePath(lower.startsWith("memory/") ? trimmed : `memory/${trimmed}`);
  }
  const segments = trimmed
    .replace(/\\/g, "/")
    .split("/")
    .map((segment) => sanitizeMemoryPathSegment(segment))
    .filter(Boolean);
  if (segments.length === 0) {
    return "MEMORY.md";
  }
  return `memory/${segments.join("/")}.md`;
}

function deriveMemoryScopeFromPath(relPath: string): string {
  const normalized = relPath.replace(/\\/g, "/").trim();
  if (!normalized || /^memory\.md$/i.test(normalized)) {
    return "memory";
  }
  if (/^memory\//i.test(normalized) && normalized.toLowerCase().endsWith(".md")) {
    return normalized.slice("memory/".length, -".md".length) || "memory";
  }
  return normalized;
}

function buildMemorySourceLink(relPath: string, startLine: number, endLine: number): string {
  const lineRange =
    startLine === endLine ? `#L${startLine}` : `#L${startLine}-L${endLine}`;
  return `${relPath}${lineRange}`;
}

function encodeMemoryPointer(pointer: QyphaMemoryPointer): string {
  return `qlmem:${Buffer.from(JSON.stringify(pointer), "utf-8").toString("base64url")}`;
}

function decodeMemoryPointer(memoryId: string): QyphaMemoryPointer | null {
  const trimmed = memoryId.trim();
  if (!trimmed.toLowerCase().startsWith("qlmem:")) {
    return null;
  }
  const encoded = trimmed.slice("qlmem:".length);
  if (!encoded) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf-8")) as
      | Partial<QyphaMemoryPointer>
      | undefined;
    if (
      parsed?.v !== 1 ||
      typeof parsed.actor_id !== "string" ||
      typeof parsed.scope !== "string" ||
      typeof parsed.path !== "string" ||
      typeof parsed.from !== "number" ||
      typeof parsed.lines !== "number" ||
      typeof parsed.content_hash !== "string"
    ) {
      return null;
    }
    return {
      v: 1,
      actor_id: parsed.actor_id,
      scope: parsed.scope,
      path: parsed.path,
      from: Math.max(1, Math.floor(parsed.from)),
      lines: Math.max(1, Math.floor(parsed.lines)),
      content_hash: parsed.content_hash,
    };
  } catch {
    return null;
  }
}

function buildMemoryEntry(params: {
  actorId: string;
  scope: string;
  relPath: string;
  from: number;
  lines: number;
  content: string;
  sourceLinks?: string[];
}): MemoryEntry {
  const endLine = params.from + Math.max(1, params.lines) - 1;
  const content = params.content.trimEnd();
  return {
    memory_id: encodeMemoryPointer({
      v: 1,
      actor_id: params.actorId,
      scope: params.scope,
      path: params.relPath,
      from: params.from,
      lines: Math.max(1, params.lines),
      content_hash: hashMemoryContent(content),
    }),
    actor_id: params.actorId,
    scope: params.scope,
    content,
    source_links:
      params.sourceLinks && params.sourceLinks.length > 0
        ? params.sourceLinks
        : [buildMemorySourceLink(params.relPath, params.from, endLine)],
  };
}

async function resolveMemoryRuntimeContext(params: {
  actorId: string;
  metadata?: Record<string, string>;
  purpose?: "default" | "status";
}) {
  debugLog(
    `memory:context:start actor=${params.actorId} purpose=${params.purpose ?? "default"}`,
  );
  const actor = resolveEmbeddedActorContext({
    actorId: params.actorId,
    metadata: params.metadata,
  });
  const cfg = buildEmbeddedActorCapabilityConfig({
    actorId: actor.actorId,
    metadata: params.metadata,
  });
  const memory = await getMemorySearchManager({
    cfg,
    agentId: actor.agentId,
    purpose: params.purpose,
  });
  debugLog(
    `memory:context:manager actor=${actor.agentId} available=${memory.manager ? "yes" : "no"}`,
  );
  if (!memory.manager) {
    throw new Error(memory.error ?? "embedded OpenClaw memory runtime is unavailable");
  }
  return {
    cfg,
    actor,
    manager: memory.manager,
  };
}

async function readMemoryEntryFromPointer(params: {
  pointer: QyphaMemoryPointer;
  metadata?: Record<string, string>;
}): Promise<MemoryEntry | null> {
  const result = await readMemoryFileSlice({
    actorId: params.pointer.actor_id,
    metadata: params.metadata,
    relPath: params.pointer.path,
    from: params.pointer.from,
    lines: params.pointer.lines,
  });
  const content = result.text.trimEnd();
  if (!content) {
    return null;
  }
  return buildMemoryEntry({
    actorId: params.pointer.actor_id,
    scope: params.pointer.scope,
    relPath: result.path || params.pointer.path,
    from: params.pointer.from,
    lines: params.pointer.lines,
    content,
  });
}

async function readMemoryFileSlice(params: {
  actorId: string;
  relPath: string;
  from?: number;
  lines?: number;
  metadata?: Record<string, string>;
}): Promise<{ text: string; path: string }> {
  const workspaceDir = resolveWorkspaceDir(params.metadata, params.actorId);
  const absolutePath = path.resolve(workspaceDir, params.relPath);
  const raw = await fsp.readFile(absolutePath, "utf-8").catch((error: NodeJS.ErrnoException) => {
    if (error?.code === "ENOENT") {
      return "";
    }
    throw error;
  });
  const normalized = raw.replace(/\r\n/g, "\n");
  if (params.from === undefined && params.lines === undefined) {
    return { text: normalized, path: params.relPath };
  }
  const fileLines = normalized.split("\n");
  const start = Math.max(1, Math.floor(params.from ?? 1));
  const count = Math.max(1, Math.floor(params.lines ?? fileLines.length));
  const slice = fileLines.slice(start - 1, start - 1 + count);
  return {
    text: slice.join("\n"),
    path: params.relPath,
  };
}

async function listMemoryRelativePaths(params: {
  actorId: string;
  metadata?: Record<string, string>;
}): Promise<string[]> {
  const workspaceDir = resolveWorkspaceDir(params.metadata, params.actorId);
  const discovered = new Set<string>();
  const queue: string[] = [];
  const addPath = (value: string) => {
    const normalized = value.replace(/\\/g, "/").trim();
    if (!normalized || discovered.has(normalized)) {
      return;
    }
    discovered.add(normalized);
    queue.push(normalized);
  };

  addPath("MEMORY.md");
  const memoryDir = path.resolve(workspaceDir, "memory");
  const walk = async (currentDir: string, currentRelDir: string) => {
    const entries = await fsp.readdir(currentDir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const nextRelDir = currentRelDir ? `${currentRelDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await walk(path.resolve(currentDir, entry.name), nextRelDir);
        continue;
      }
      if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) {
        addPath(`memory/${nextRelDir}`);
      }
    }
  };
  await walk(memoryDir, "");
  return queue;
}

function findMemoryMatchLineIndexes(lines: string[], query: string): number[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return [];
  }
  const queryTokens = normalizedQuery.split(/\s+/).filter(Boolean);
  const matches: number[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const normalizedLine = (lines[index] ?? "").trim().toLowerCase();
    if (!normalizedLine) {
      continue;
    }
    if (normalizedLine.includes(normalizedQuery)) {
      matches.push(index);
      continue;
    }
    if (queryTokens.length > 1 && queryTokens.every((token) => normalizedLine.includes(token))) {
      matches.push(index);
    }
  }
  return matches;
}

async function searchMemoryEntriesByFileScan(params: {
  actorId: string;
  query: string;
  limit: number;
  metadata?: Record<string, string>;
}): Promise<MemoryEntry[]> {
  const relPaths = await listMemoryRelativePaths({
    actorId: params.actorId,
    metadata: params.metadata,
  });
  const matches: MemoryEntry[] = [];
  for (const relPath of relPaths) {
    if (matches.length >= params.limit) {
      break;
    }
    const file = await readMemoryFileSlice({
      actorId: params.actorId,
      metadata: params.metadata,
      relPath,
    });
    if (!file.text.trim()) {
      continue;
    }
    const lines = file.text.replace(/\r\n/g, "\n").split("\n");
    const lineIndexes = findMemoryMatchLineIndexes(lines, params.query);
    for (const matchIndex of lineIndexes) {
      if (matches.length >= params.limit) {
        break;
      }
      const start = Math.max(1, matchIndex + 1 - 2);
      const end = Math.min(lines.length, matchIndex + 1 + 2);
      const snippet = lines.slice(start - 1, end).join("\n").trimEnd();
      if (!snippet) {
        continue;
      }
      matches.push(
        buildMemoryEntry({
          actorId: params.actorId,
          scope: deriveMemoryScopeFromPath(relPath),
          relPath,
          from: start,
          lines: Math.max(1, end - start + 1),
          content: snippet,
        }),
      );
    }
  }
  return matches;
}

function renderMemoryMarkdownEntry(params: {
  scope: string;
  content: string;
  sourceLinks: string[];
}): string {
  const blocks = [
    `## ${new Date().toISOString()} (${params.scope})`,
    params.content.trim(),
    params.sourceLinks.length > 0
      ? ["Sources:", ...params.sourceLinks.map((link) => `- ${link}`)].join("\n")
      : "",
  ].filter((block) => block.trim().length > 0);
  return `${blocks.join("\n\n")}\n`;
}

async function appendMemoryEntry(params: {
  actorId: string;
  scope: string;
  content: string;
  sourceLinks: string[];
  metadata?: Record<string, string>;
}): Promise<MemoryEntry> {
  debugLog(`memory_write:append:start actor=${params.actorId} scope=${params.scope}`);
  const context = await resolveMemoryRuntimeContext({
    actorId: params.actorId,
    metadata: params.metadata,
  });
  const relPath = resolveMemoryScopeRelativePath(params.scope);
  const workspaceDir = resolveWorkspaceDir(params.metadata, params.actorId);
  const absolutePath = path.resolve(workspaceDir, relPath);
  const existing = await fsp.readFile(absolutePath, "utf-8").catch((error: NodeJS.ErrnoException) => {
    if (error?.code === "ENOENT") {
      return "";
    }
    throw error;
  });
  const normalizedExisting = existing.replace(/\r\n/g, "\n");
  const prefix =
    normalizedExisting.trim().length === 0
      ? ""
      : normalizedExisting.endsWith("\n")
        ? "\n"
        : "\n\n";
  const rendered = renderMemoryMarkdownEntry({
    scope: deriveMemoryScopeFromPath(relPath),
    content: params.content,
    sourceLinks: params.sourceLinks,
  });
  const prelude = `${normalizedExisting}${prefix}`;
  const startLine = prelude.length === 0 ? 1 : countTextLines(prelude);
  await fsp.mkdir(path.dirname(absolutePath), { recursive: true });
  await fsp.writeFile(absolutePath, `${prelude}${rendered}`, "utf-8");
  debugLog(`memory_write:append:file_written path=${absolutePath}`);
  return buildMemoryEntry({
    actorId: context.actor.actorId,
    scope: deriveMemoryScopeFromPath(relPath),
    relPath,
    from: startLine,
    lines: countTextLines(rendered),
    content: rendered.trimEnd(),
    sourceLinks:
      params.sourceLinks.length > 0 ? params.sourceLinks : undefined,
  });
}

function buildCompressedMemoryContent(params: {
  scope: string;
  sourceText: string;
}): string | null {
  const normalized = params.sourceText.replace(/\r\n/g, "\n").trim();
  if (!normalized || normalized.length < 1_200) {
    return null;
  }
  const lines = normalized
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const headings = lines
    .filter((line) => /^#{1,6}\s+/.test(line))
    .map((line) => line.replace(/^#{1,6}\s+/, "").trim())
    .slice(0, 8);
  const bullets = lines
    .filter((line) => /^[-*]\s+/.test(line))
    .map((line) => line.replace(/^[-*]\s+/, "").trim())
    .slice(0, 12);
  const plainHighlights = lines
    .filter((line) => !/^#{1,6}\s+/.test(line) && !/^[-*]\s+/.test(line))
    .filter((line) => line.length > 20)
    .slice(0, 10)
    .map((line) => (line.length > 220 ? `${line.slice(0, 217).trimEnd()}...` : line));

  const summaryLines = [
    `Compressed summary for scope "${params.scope}".`,
    `Original content length: ${normalized.length} characters.`,
  ];
  if (headings.length > 0) {
    summaryLines.push("", "Key headings:");
    summaryLines.push(...headings.map((heading) => `- ${heading}`));
  }
  if (bullets.length > 0) {
    summaryLines.push("", "Key bullets:");
    summaryLines.push(...bullets.map((bullet) => `- ${bullet}`));
  } else if (plainHighlights.length > 0) {
    summaryLines.push("", "Key excerpts:");
    summaryLines.push(...plainHighlights.map((line) => `- ${line}`));
  }
  const summary = summaryLines.join("\n").trim();
  return summary.length > 0 ? summary : null;
}

async function runMemoryGet(payload: {
  request: MemoryGetRequest;
  metadata?: Record<string, string>;
}) {
  const pointer = decodeMemoryPointer(payload.request.memory_id);
  if (!pointer || pointer.actor_id !== payload.request.actor_id.trim()) {
    return {
      ok: true as const,
    };
  }
  const memoryEntry = await readMemoryEntryFromPointer({
    pointer,
    metadata: payload.metadata,
  });
  return memoryEntry ? { ok: true as const, memory_entry: memoryEntry } : { ok: true as const };
}

async function runMemorySearch(payload: {
  request: MemorySearchRequest;
  metadata?: Record<string, string>;
}) {
  const query = payload.request.query.trim();
  if (!query) {
    throw new Error("query is required");
  }
  const limit =
    typeof payload.request.limit === "number" && Number.isFinite(payload.request.limit)
      ? Math.max(1, Math.floor(payload.request.limit))
      : 8;
  const actorId = payload.request.actor_id.trim();
  const directMatches = await searchMemoryEntriesByFileScan({
    actorId,
    query,
    limit,
    metadata: payload.metadata,
  });
  if (directMatches.length > 0) {
    return {
      ok: true as const,
      memory_entries: directMatches,
    };
  }

  const context = await resolveMemoryRuntimeContext({
    actorId,
    metadata: payload.metadata,
  });
  const results = await Promise.race([
    context.manager.search(query, {
      maxResults: limit,
      sessionKey: resolveMetadataString(payload.metadata, "session_id"),
    }),
    new Promise<never>((_, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("embedded memory search timed out"));
      }, 5_000);
      timer.unref?.();
    }),
  ]);
  return {
    ok: true as const,
    memory_entries: results.slice(0, limit).map((entry) =>
      buildMemoryEntry({
        actorId,
        scope: deriveMemoryScopeFromPath(entry.path),
        relPath: entry.path,
        from: entry.startLine,
        lines: Math.max(1, entry.endLine - entry.startLine + 1),
        content: entry.snippet,
      }),
    ),
  };
}

async function runMemoryWrite(payload: {
  request: MemoryWriteRequest;
  metadata?: Record<string, string>;
}) {
  debugLog(`memory_write:start actor=${payload.request.actor_id}`);
  const content = payload.request.content.trim();
  if (!content) {
    throw new Error("content is required");
  }
  const sourceLinks = Array.from(
    new Set(
      (payload.request.source_links ?? [])
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  );
  return {
    ok: true as const,
    memory_entry: await appendMemoryEntry({
      actorId: payload.request.actor_id,
      scope: payload.request.scope,
      content,
      sourceLinks,
      metadata: payload.metadata,
    }),
  };
}

async function runMemoryCompress(payload: {
  request: MemoryCompressRequest;
  metadata?: Record<string, string>;
}) {
  const relPath = resolveMemoryScopeRelativePath(payload.request.scope);
  const current = await readMemoryFileSlice({
    actorId: payload.request.actor_id,
    metadata: payload.metadata,
    relPath,
  });
  const compressed = buildCompressedMemoryContent({
    scope: deriveMemoryScopeFromPath(relPath),
    sourceText: current.text,
  });
  if (!compressed) {
    return {
      ok: true as const,
    };
  }
  return {
    ok: true as const,
    memory_entry: await appendMemoryEntry({
      actorId: payload.request.actor_id,
      scope: payload.request.scope,
      content: compressed,
      sourceLinks: [buildMemorySourceLink(relPath, 1, Math.max(1, countTextLines(current.text)))],
      metadata: payload.metadata,
    }),
  };
}

async function runMemoryStalenessCheck(payload: {
  request: MemoryStalenessCheckRequest;
  metadata?: Record<string, string>;
}) {
  const pointer = decodeMemoryPointer(payload.request.memory_id);
  if (!pointer || pointer.actor_id !== payload.request.actor_id.trim()) {
    return {
      ok: true as const,
      memory_id: payload.request.memory_id,
      stale: true,
      rationale: "Unsupported memory_id format for embedded OpenClaw memory bridge.",
    };
  }
  const current = await readMemoryEntryFromPointer({
    pointer,
    metadata: payload.metadata,
  });
  if (!current) {
    return {
      ok: true as const,
      memory_id: payload.request.memory_id,
      stale: true,
      rationale: "The backing memory snippet is no longer available.",
    };
  }
  const stale = hashMemoryContent(current.content) !== pointer.content_hash;
  return {
    ok: true as const,
    memory_id: payload.request.memory_id,
    stale,
    ...(stale
      ? { rationale: "The backing memory snippet changed since this memory_id was issued." }
      : {}),
  };
}

function completedOsResult(params?: {
  stdout?: string;
  stderr?: string;
  paths?: string[];
}): WorkerRuntimeStatusResult {
  return {
    ok: true,
    status: "completed",
    ...(params?.stdout ? { stdout: params.stdout } : {}),
    ...(params?.stderr ? { stderr: params.stderr } : {}),
    paths: params?.paths ?? [],
  };
}

function blockedOsResult(message: string, paths?: string[]): WorkerRuntimeStatusResult {
  return {
    ok: true,
    status: "blocked",
    stderr: message,
    paths: paths ?? [],
  };
}

function failedOsResult(message: string, paths?: string[]): WorkerRuntimeStatusResult {
  return {
    ok: true,
    status: "failed",
    stderr: message,
    paths: paths ?? [],
  };
}

function normalizeOptionalPathLike(value: unknown, metadata?: Record<string, string>): string | undefined {
  if (typeof value !== "string" || !value.trim()) {
    return undefined;
  }
  return resolvePathFromWorkspace(value, metadata);
}

function resolveOperationPath(value: unknown, metadata?: Record<string, string>): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("operation path is required");
  }
  return resolvePathFromWorkspace(value, metadata);
}

function isWriteLikeOsOperation(kind: string): boolean {
  return new Set([
    "write_text",
    "make_dir",
    "move_path",
    "copy_path",
    "delete_path",
    "archive",
    "extract",
    "open_path",
    "launch_app",
    "clipboard_write",
    "notify",
    "run_command",
  ]).has(kind);
}

async function runHostCommand(
  argv: string[],
  options?: {
    cwd?: string;
    timeoutMs?: number;
    env?: Record<string, string>;
    input?: string;
  },
) {
  return await runCommandWithTimeout(argv, {
    timeoutMs: options?.timeoutMs ?? 30_000,
    ...(options?.cwd ? { cwd: options.cwd } : {}),
    ...(options?.env ? { env: options.env } : {}),
    ...(options?.input !== undefined ? { input: options.input } : {}),
  });
}

async function readClipboardText(): Promise<string> {
  const attempts: string[][] = [
    ["pbpaste"],
    ["xclip", "-selection", "clipboard", "-o"],
    ["wl-paste"],
    ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
  ];
  for (const argv of attempts) {
    try {
      const result = await runHostCommand(argv, { timeoutMs: 3_000 });
      if (result.code === 0 && !result.killed) {
        return result.stdout;
      }
    } catch {
      // try next clipboard backend
    }
  }
  throw new Error("Clipboard read is unavailable on this host");
}

async function sendHostNotification(title: string, body: string): Promise<void> {
  const attempts: string[][] =
    process.platform === "darwin"
      ? [
          [
            "osascript",
            "-e",
            `display notification ${JSON.stringify(body)} with title ${JSON.stringify(title)}`,
          ],
        ]
      : process.platform === "win32"
        ? [
            [
              "powershell",
              "-NoProfile",
              "-Command",
              `[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.MessageBox]::Show(${JSON.stringify(body)}, ${JSON.stringify(title)})`,
            ],
          ]
        : [["notify-send", title, body]];
  for (const argv of attempts) {
    try {
      const result = await runHostCommand(argv, { timeoutMs: 5_000 });
      if (result.code === 0 && !result.killed) {
        return;
      }
    } catch {
      // try next notifier backend
    }
  }
  throw new Error("Notification delivery is unavailable on this host");
}

async function openPathOnHost(targetPath: string): Promise<void> {
  const argv =
    process.platform === "darwin"
      ? ["open", targetPath]
      : process.platform === "win32"
        ? ["cmd.exe", "/d", "/s", "/c", "start", "", targetPath]
        : ["xdg-open", targetPath];
  const result = await runHostCommand(argv, { timeoutMs: 10_000 });
  if (result.code !== 0 || result.killed) {
    throw new Error(result.stderr.trim() || `Failed to open path: ${targetPath}`);
  }
}

async function createArchiveViaHostTools(params: {
  source: string;
  destination: string;
  format: string;
}): Promise<void> {
  const source = path.resolve(params.source);
  const destination = path.resolve(params.destination);
  await fsp.mkdir(path.dirname(destination), { recursive: true });

  const normalizedFormat = params.format.trim().toLowerCase();
  if (normalizedFormat === "zip") {
    const cwd = path.dirname(source);
    const base = path.basename(source);
    const result = await runHostCommand(["zip", "-r", destination, base], {
      cwd,
      timeoutMs: 120_000,
    });
    if (result.code !== 0 || result.killed) {
      throw new Error(result.stderr.trim() || "zip archive creation failed");
    }
    return;
  }

  const cwd = path.dirname(source);
  const base = path.basename(source);
  const argv =
    normalizedFormat === "tar.gz" || destination.toLowerCase().endsWith(".tgz")
      ? ["tar", "-czf", destination, base]
      : ["tar", "-cf", destination, base];
  const result = await runHostCommand(argv, { cwd, timeoutMs: 120_000 });
  if (result.code !== 0 || result.killed) {
    throw new Error(result.stderr.trim() || "tar archive creation failed");
  }
}

async function runOsExecute(payload: {
  request: OsOperationRequest;
  metadata?: Record<string, string>;
}) {
  const { request } = payload;
  const operation = request.operation ?? { kind: "" };
  const kind = typeof operation.kind === "string" ? operation.kind.trim().toLowerCase() : "";
  if (!kind) {
    throw new Error("operation.kind is required");
  }

  if (request.access_mode !== "full_access" && isWriteLikeOsOperation(kind)) {
    return blockedOsResult(
      `OS operation "${kind}" requires full_access mode.`,
      [],
    );
  }

  try {
    switch (kind) {
      case "read_text": {
        const filePath = resolveOperationPath(operation.path, payload.metadata);
        const content = await fsp.readFile(filePath, "utf-8");
        return completedOsResult({ stdout: content, paths: [filePath] });
      }
      case "write_text": {
        const filePath = resolveOperationPath(operation.path, payload.metadata);
        const content = typeof operation.content === "string" ? operation.content : "";
        const createParents = operation.create_parents === true;
        if (createParents) {
          await fsp.mkdir(path.dirname(filePath), { recursive: true });
        }
        await fsp.writeFile(filePath, content, "utf-8");
        return completedOsResult({ paths: [filePath] });
      }
      case "list_dir": {
        const dirPath = resolveOperationPath(operation.path, payload.metadata);
        const entries = await fsp.readdir(dirPath);
        const paths = entries.map((entry) => path.resolve(dirPath, entry));
        return completedOsResult({ stdout: paths.join("\n"), paths });
      }
      case "search_files": {
        const root = resolveOperationPath(operation.root, payload.metadata);
        const pattern = typeof operation.pattern === "string" ? operation.pattern.trim() : "";
        if (!pattern) {
          throw new Error("search_files requires a pattern");
        }
        const result = await invokeBundledCapabilityTool(payload.metadata, "search_files", {
          path: root,
          pattern,
          excludePatterns: ["node_modules/**", ".git/**", "dist/**"],
        });
        const text = extractToolText(result);
        let paths: string[];
        try {
          const parsed = JSON.parse(text) as unknown;
          paths = Array.isArray(parsed)
            ? parsed
                .filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
                .map((entry) => resolvePathFromWorkspace(entry, payload.metadata))
            : [];
        } catch {
          paths = text
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .map((entry) => resolvePathFromWorkspace(entry, payload.metadata));
        }
        return completedOsResult({ stdout: text, paths });
      }
      case "make_dir": {
        const dirPath = resolveOperationPath(operation.path, payload.metadata);
        await fsp.mkdir(dirPath, { recursive: true });
        return completedOsResult({ paths: [dirPath] });
      }
      case "move_path": {
        const from = resolveOperationPath(operation.from, payload.metadata);
        const to = resolveOperationPath(operation.to, payload.metadata);
        await fsp.mkdir(path.dirname(to), { recursive: true });
        await fsp.rename(from, to);
        return completedOsResult({ paths: [to] });
      }
      case "copy_path": {
        const from = resolveOperationPath(operation.from, payload.metadata);
        const to = resolveOperationPath(operation.to, payload.metadata);
        await fsp.mkdir(path.dirname(to), { recursive: true });
        await fsp.cp(from, to, { recursive: true, force: true });
        return completedOsResult({ paths: [to] });
      }
      case "delete_path": {
        const targetPath = resolveOperationPath(operation.path, payload.metadata);
        const recursive = operation.recursive === true;
        await fsp.rm(targetPath, { recursive, force: true });
        return completedOsResult({ paths: [targetPath] });
      }
      case "archive": {
        const source = resolveOperationPath(operation.source, payload.metadata);
        const destination = resolveOperationPath(operation.destination, payload.metadata);
        const format = typeof operation.format === "string" ? operation.format : "tar";
        await createArchiveViaHostTools({ source, destination, format });
        return completedOsResult({ paths: [destination] });
      }
      case "extract": {
        const archive = resolveOperationPath(operation.archive, payload.metadata);
        const destination = resolveOperationPath(operation.destination, payload.metadata);
        await fsp.mkdir(destination, { recursive: true });
        await extractArchive({
          archivePath: archive,
          destDir: destination,
          timeoutMs: 120_000,
        });
        return completedOsResult({ paths: [destination] });
      }
      case "open_path": {
        const targetPath = resolveOperationPath(operation.path, payload.metadata);
        await openPathOnHost(targetPath);
        return completedOsResult({ paths: [targetPath] });
      }
      case "launch_app":
      case "run_command": {
        const command =
          kind === "run_command"
            ? (operation.command as Record<string, unknown> | undefined)
            : (operation.command as Record<string, unknown> | undefined);
        const program = typeof command?.program === "string" ? command.program.trim() : "";
        if (!program) {
          throw new Error(`${kind} requires command.program`);
        }
        const args = Array.isArray(command?.args)
          ? command.args.filter((entry): entry is string => typeof entry === "string")
          : [];
        const cwd = normalizeOptionalPathLike(command?.cwd, payload.metadata);
        const timeoutMs =
          typeof command?.timeout_ms === "number" && Number.isFinite(command.timeout_ms)
            ? Math.max(1_000, Math.floor(command.timeout_ms))
            : 60_000;
        const env =
          command?.env && typeof command.env === "object" && !Array.isArray(command.env)
            ? Object.fromEntries(
                Object.entries(command.env as Record<string, unknown>)
                  .filter(([, value]) => value !== undefined && value !== null)
                  .map(([key, value]) => [key, String(value)]),
              )
            : undefined;
        const result = await runHostCommand([program, ...args], {
          cwd,
          timeoutMs,
          env,
        });
        return {
          ok: true as const,
          status: result.code === 0 && !result.killed ? "completed" : "failed",
          ...(result.stdout.trim() ? { stdout: result.stdout } : {}),
          ...(result.stderr.trim() ? { stderr: result.stderr } : {}),
          paths: cwd ? [cwd] : [],
        };
      }
      case "list_processes": {
        const argv =
          process.platform === "win32" ? ["tasklist"] : ["ps", "-A", "-o", "pid=,comm="];
        const result = await runHostCommand(argv, { timeoutMs: 15_000 });
        return {
          ok: true as const,
          status: result.code === 0 && !result.killed ? "completed" : "failed",
          ...(result.stdout.trim() ? { stdout: result.stdout } : {}),
          ...(result.stderr.trim() ? { stderr: result.stderr } : {}),
          paths: [],
        };
      }
      case "clipboard_read": {
        const text = await readClipboardText();
        return completedOsResult({ stdout: text });
      }
      case "clipboard_write": {
        const text = typeof operation.text === "string" ? operation.text : "";
        const copied = await copyToClipboard(text);
        if (!copied) {
          return failedOsResult("Clipboard write is unavailable on this host");
        }
        return completedOsResult();
      }
      case "notify": {
        const title = typeof operation.title === "string" ? operation.title : "Qypha";
        const body = typeof operation.body === "string" ? operation.body : "";
        await sendHostNotification(title, body);
        return completedOsResult();
      }
      default:
        return blockedOsResult(`Unsupported OS operation: ${kind}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return failedOsResult(message);
  }
}

async function generateStructuredResearchJson<T>(params: {
  provider: string;
  model_id: string;
  metadata?: Record<string, string>;
  system_prompt?: string | null;
  prompt: string;
}): Promise<T> {
  const response = await generateWithProvider({
    provider: params.provider,
    model_id: params.model_id,
    system_prompt: params.system_prompt,
    messages: [{ role: "user", content: params.prompt }],
    metadata: params.metadata,
  });
  return parseJsonFromModel<T>(response.output_text);
}

function buildDocumentSections(text: string): DocumentSection[] {
  const normalized = text.replace(/\r\n/g, "\n").trim();
  if (!normalized) {
    return [];
  }

  const markdownHeadingMatches = Array.from(normalized.matchAll(/^#{1,6}\s+(.+)$/gm));
  if (markdownHeadingMatches.length > 0) {
    const sections: DocumentSection[] = [];
    for (let i = 0; i < markdownHeadingMatches.length; i++) {
      const current = markdownHeadingMatches[i];
      const next = markdownHeadingMatches[i + 1];
      const start = current.index ?? 0;
      const bodyStart = start + current[0].length;
      const end = next?.index ?? normalized.length;
      const body = normalized.slice(bodyStart, end).trim();
      sections.push({
        heading: current[1]?.trim() || `Section ${i + 1}`,
        body,
      });
    }
    return sections.filter((section) => section.body.trim().length > 0);
  }

  const paragraphs = normalized
    .split(/\n{2,}/)
    .map((part) => part.trim())
    .filter(Boolean);
  const chunkSize = 8_000;
  if (paragraphs.length <= 1 && normalized.length <= chunkSize) {
    return [{ heading: "Document", body: normalized }];
  }

  const sections: DocumentSection[] = [];
  let current = "";
  let sectionIndex = 1;
  for (const paragraph of paragraphs.length > 0 ? paragraphs : [normalized]) {
    const next = current ? `${current}\n\n${paragraph}` : paragraph;
    if (current && next.length > chunkSize) {
      sections.push({
        heading: `Section ${sectionIndex}`,
        body: current,
      });
      sectionIndex += 1;
      current = paragraph;
      continue;
    }
    current = next;
  }
  if (current) {
    sections.push({
      heading: sections.length === 0 ? "Document" : `Section ${sectionIndex}`,
      body: current,
    });
  }
  return sections;
}

async function ensureBrowserSession(spec: BrowserSessionSpec): Promise<BrowserSessionState> {
  const sessionId = normalizeSessionId(spec.session_id);
  const allowedDomains = normalizeAllowedDomains(spec.allowed_domains);
  const mode = spec.mode === "ephemeral" ? "ephemeral" : "persistent";
  const profile = browserProfileForSession(sessionId);
  const existing = browserSessions.get(sessionId);
  const nextState: BrowserSessionState = existing
    ? {
        ...existing,
        mode,
        allowedDomains,
      }
    : {
        sessionId,
        mode,
        allowedDomains,
        profile,
      };

  const knownProfiles = await browserProfiles(undefined);
  const hasProfile = knownProfiles.some((entry) => entry.name.trim().toLowerCase() === profile);
  if (!hasProfile) {
    try {
      await browserCreateProfile(undefined, { name: profile });
    } catch (error) {
      const message = String(error).toLowerCase();
      if (!message.includes("already exists")) {
        throw error;
      }
    }
  }

  await browserStart(undefined, { profile });
  browserSessions.set(sessionId, nextState);
  return nextState;
}

async function ensureDefaultBrowserSession(
  sessionIdRaw: string,
  metadata?: Record<string, string>,
): Promise<BrowserSessionState> {
  const sessionId = normalizeSessionId(sessionIdRaw);
  const existing = browserSessions.get(sessionId);
  if (existing) {
    await browserStart(undefined, { profile: existing.profile });
    return existing;
  }
  return await ensureBrowserSession({
    session_id: sessionId,
    mode: "persistent",
    allowed_domains: [],
    metadata,
  });
}

async function ensureResearchBrowserSession(
  sessionIdRaw: string,
  scope: ResearchSourceScope | undefined,
  metadata?: Record<string, string>,
): Promise<BrowserSessionState> {
  const normalizedScope = normalizeResearchSourceScope(scope);
  if (
    normalizedScope?.allow_open_web === false &&
    (normalizedScope.allowed_domains?.length ?? 0) === 0
  ) {
    throw new Error("Research scope disables open web access and does not allow any domains.");
  }
  if ((normalizedScope?.allowed_domains?.length ?? 0) > 0) {
    return await ensureBrowserSession({
      session_id: normalizeSessionId(sessionIdRaw),
      mode: "persistent",
      allowed_domains: normalizedScope?.allowed_domains ?? [],
      metadata,
    });
  }
  return await ensureDefaultBrowserSession(sessionIdRaw, metadata);
}

function normalizeBrowserTarget(target: string | null | undefined): {
  ref?: string;
  selector?: string;
} {
  const trimmed = target?.trim();
  if (!trimmed) {
    return {};
  }
  if (trimmed.startsWith("selector:")) {
    return { selector: trimmed.slice("selector:".length).trim() };
  }
  return { ref: trimmed };
}

async function snapshotBrowserSession(state: BrowserSessionState): Promise<BrowserSnapshotSuccess> {
  await browserStart(undefined, { profile: state.profile });
  const snapshot = await browserSnapshot(undefined, {
    format: "ai",
    mode: "efficient",
    targetId: state.targetId,
    profile: state.profile,
  });
  if (snapshot.format !== "ai") {
    throw new Error("Embedded browser snapshot returned an unexpected format.");
  }
  state.targetId = snapshot.targetId;
  state.url = snapshot.url;
  browserSessions.set(state.sessionId, state);
  return {
    ok: true as const,
    session_id: state.sessionId,
    url: snapshot.url,
    markdown: snapshot.snapshot?.trim() ?? "",
  };
}

async function openBrowserUrl(state: BrowserSessionState, url: string): Promise<void> {
  assertUrlAllowed(url, state.allowedDomains);
  await browserStart(undefined, { profile: state.profile });
  if (state.targetId) {
    const navigated = await browserNavigate(undefined, {
      url,
      targetId: state.targetId,
      profile: state.profile,
    });
    state.targetId = navigated.targetId;
    state.url = navigated.url ?? url;
  } else {
    const opened = await browserOpenTab(undefined, url, {
      profile: state.profile,
    });
    state.targetId = opened.targetId;
    state.url = opened.url ?? url;
  }
  browserSessions.set(state.sessionId, state);
}

async function runBrowserStartSession(payload: BrowserSessionSpec) {
  const state = await ensureBrowserSession(payload);
  return {
    ok: true as const,
    session_id: state.sessionId,
    ...(state.url ? { url: state.url } : {}),
  };
}

async function runBrowserOpen(payload: BrowserOpenRequest) {
  const url = payload.url.trim();
  if (!url) {
    throw new Error("url is required");
  }
  const state = await ensureDefaultBrowserSession(payload.session_id, payload.metadata);
  await openBrowserUrl(state, url);
  return await snapshotBrowserSession(state);
}

async function runBrowserSnapshot(payload: {
  session_id: string;
  metadata?: Record<string, string>;
}) {
  const state = await ensureDefaultBrowserSession(payload.session_id, payload.metadata);
  return await snapshotBrowserSession(state);
}

function findMatchesInMarkdown(
  markdown: string,
  query: string,
  maxMatches: number,
): ResearchPageMatch[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return [];
  }
  const queryTokens = normalizedQuery.split(/\s+/).filter(Boolean);
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const matches: ResearchPageMatch[] = [];
  let currentHeading: string | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index] ?? "";
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const headingMatch = line.match(/^#{1,6}\s+(.+)$/);
    if (headingMatch?.[1]?.trim()) {
      currentHeading = headingMatch[1].trim();
    }

    const lowerLine = line.toLowerCase();
    const exactMatch = lowerLine.includes(normalizedQuery);
    const tokenMatch =
      !exactMatch &&
      queryTokens.length > 1 &&
      queryTokens.every((token) => lowerLine.includes(token));
    if (!exactMatch && !tokenMatch) {
      continue;
    }

    matches.push({
      line_number: index + 1,
      ...(currentHeading ? { heading: currentHeading } : {}),
      excerpt: line,
    });
    if (matches.length >= maxMatches) {
      break;
    }
  }

  return matches;
}

function countQueryTokenHits(text: string, query: string): number {
  const lowerText = text.trim().toLowerCase();
  if (!lowerText) {
    return 0;
  }
  const tokens = query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => token.length >= 3);
  if (tokens.length === 0) {
    return 0;
  }
  return tokens.reduce((count, token) => count + (lowerText.includes(token) ? 1 : 0), 0);
}

function inferInspectBudget(payload: ResearchInspectRequest): number {
  const requested = Math.floor(payload.max_sources ?? 0);
  if (requested > 0) {
    return Math.max(1, Math.min(10, requested));
  }
  const query = payload.query.trim();
  if (!query) {
    return 4;
  }
  if (looksLikePaperResearchPrompt(query)) {
    return 7;
  }
  if (looksLikeResearchTaskPrompt(query) || looksLikeCurrentInfoPrompt(query)) {
    return 6;
  }
  if (looksLikeRepoPrompt(query) || looksLikeBrowserPrompt(query)) {
    return 5;
  }
  if (looksLikeCasualPrompt(query)) {
    return 3;
  }
  return 4;
}

function inferInspectMaxChars(query: string, source: ResearchSource): number {
  const classification = classifyResearchSource(source);
  if (classification === "paper" || classification === "official_doc") {
    return 50_000;
  }
  if (looksLikeResearchTaskPrompt(query) || looksLikePaperResearchPrompt(query)) {
    return 45_000;
  }
  return 30_000;
}

function looksLikeDynamicOrBlockedPage(text: string): boolean {
  const lower = text.trim().toLowerCase();
  if (!lower) {
    return false;
  }
  return [
    "enable javascript",
    "javascript is required",
    "please turn on javascript",
    "loading...",
    "checking your browser",
    "access denied",
    "sign in to continue",
    "log in to continue",
    "please wait while we verify",
    "client-side rendering",
  ].some((pattern) => lower.includes(pattern));
}

function shouldEscalateInspectToBrowser(params: {
  source: ResearchSource;
  query: string;
  extractedText: string;
  extractor?: string;
  warning?: string;
  contentType?: string;
}): { escalate: boolean; reason?: string } {
  const classification = classifyResearchSource(params.source);
  const contentType = params.contentType?.trim().toLowerCase() ?? "";
  const extractor = params.extractor?.trim().toLowerCase() ?? "";
  const extractedText = params.extractedText.trim();
  const warning = params.warning?.trim().toLowerCase() ?? "";
  const queryHits = countQueryTokenHits(extractedText, params.query);

  if (classification === "paper" || contentType.includes("pdf")) {
    return { escalate: false };
  }
  if (looksLikeDynamicOrBlockedPage(extractedText)) {
    return { escalate: true, reason: "fetch output looks dynamic, blocked, or incomplete." };
  }
  if (extractedText.length < 1_200 && contentType.includes("html")) {
    return { escalate: true, reason: "HTML fetch returned too little readable content." };
  }
  if (
    queryHits === 0 &&
    contentType.includes("html") &&
    (classification === "official_doc" || classification === "repo") &&
    extractedText.length < 8_000
  ) {
    return {
      escalate: true,
      reason: "Important query terms were not found in the fetched HTML content.",
    };
  }
  if (
    (extractor === "raw-html" || extractor === "raw") &&
    contentType.includes("html") &&
    extractedText.length < 3_000
  ) {
    return { escalate: true, reason: "Only low-confidence raw HTML extraction was available." };
  }
  if (warning.includes("no readable text") || warning.includes("returned no content")) {
    return { escalate: true, reason: "Fetch warning indicates poor extraction quality." };
  }
  return { escalate: false };
}

async function inspectSourceViaBrowser(params: {
  sessionId: string;
  source: ResearchSource;
  query: string;
  scope: ResearchSourceScope | undefined;
  metadata?: Record<string, string>;
  escalationReason: string;
}): Promise<{
  markdown: string;
  consultedSource: ConsultedSourceRecord;
  actionLog: ResearchActionLogEntry[];
  matches: ResearchPageMatch[];
}> {
  const state = await ensureResearchBrowserSession(params.sessionId, params.scope, params.metadata);
  await openBrowserUrl(state, params.source.url);
  const snapshot = await snapshotBrowserSession(state);
  const markdown = snapshot.markdown ?? "";
  const matches = findMatchesInMarkdown(markdown, params.query, 8);
  const consultedSource = buildConsultedSourceRecord({
    source: params.source,
    extractionMode: "browser_snapshot_ai",
    content: markdown,
    headings: extractMarkdownHeadings(markdown),
    findQueries: matches.length > 0 ? [params.query] : undefined,
    notes: `Browser escalation: ${params.escalationReason}`,
  });
  return {
    markdown,
    consultedSource,
    matches,
    actionLog: [
      createResearchActionLogEntry({
        action: "open_page",
        url: params.source.url,
        session_id: snapshot.session_id,
        note: `Browser escalation triggered: ${params.escalationReason}`,
      }),
      createResearchActionLogEntry({
        action: "find_in_page",
        url: snapshot.url ?? params.source.url,
        session_id: snapshot.session_id,
        query: params.query,
        note: `Browser snapshot produced ${matches.length} in-page match(es).`,
      }),
    ],
  };
}

function shouldPreferBrowserInspection(params: {
  fetchText: string;
  query: string;
  browserMarkdown: string;
  browserMatches: ResearchPageMatch[];
}): boolean {
  const fetchText = params.fetchText.trim();
  const browserMarkdown = params.browserMarkdown.trim();
  if (!browserMarkdown) {
    return false;
  }
  if (!fetchText) {
    return true;
  }
  const fetchHits = countQueryTokenHits(fetchText, params.query);
  const browserHits = countQueryTokenHits(browserMarkdown, params.query);
  if (browserHits > fetchHits) {
    return true;
  }
  if (params.browserMatches.length > 0 && fetchHits === 0) {
    return true;
  }
  return browserMarkdown.length > fetchText.length * 1.25 && browserMarkdown.length > 2_000;
}

async function runBrowserInteract(payload: BrowserInteractRequest) {
  const state = await ensureDefaultBrowserSession(payload.session_id, payload.metadata);
  const action = payload.action.trim().toLowerCase();
  if (!action) {
    throw new Error("action is required");
  }

  if (action === "navigate") {
    const targetUrl = payload.value?.trim() || payload.target?.trim() || "";
    if (!targetUrl) {
      throw new Error("navigate requires a target URL in value or target");
    }
    await openBrowserUrl(state, targetUrl);
    return await snapshotBrowserSession(state);
  }

  const targetId = state.targetId;
  if (!targetId) {
    throw new Error("browser session has no active tab; open a URL first");
  }

  const target = normalizeBrowserTarget(payload.target);
  let request: Parameters<typeof browserAct>[1] | undefined;
  switch (action) {
    case "click":
      request = {
        kind: "click",
        ...target,
        targetId,
      };
      break;
    case "double_click":
      request = {
        kind: "click",
        ...target,
        targetId,
        doubleClick: true,
      };
      break;
    case "type":
      if (!payload.value?.trim()) {
        throw new Error("type requires a non-empty value");
      }
      request = {
        kind: "type",
        ...target,
        targetId,
        text: payload.value.trim(),
      };
      break;
    case "press":
      request = {
        kind: "press",
        targetId,
        key: payload.value?.trim() || payload.target?.trim() || "Enter",
      };
      break;
    case "hover":
      request = {
        kind: "hover",
        ...target,
        targetId,
      };
      break;
    case "scroll_into_view":
      request = {
        kind: "scrollIntoView",
        ...target,
        targetId,
      };
      break;
    case "wait_for_text":
      request = {
        kind: "wait",
        targetId,
        text: payload.value?.trim() || payload.target?.trim() || "",
      };
      if (!request.text) {
        throw new Error("wait_for_text requires a non-empty target or value");
      }
      break;
    case "wait_for_ms": {
      const timeMsRaw = Number(payload.value?.trim() || payload.target?.trim() || "0");
      if (!Number.isFinite(timeMsRaw) || timeMsRaw < 1) {
        throw new Error("wait_for_ms requires a positive millisecond value");
      }
      request = {
        kind: "wait",
        targetId,
        timeMs: Math.floor(timeMsRaw),
      };
      break;
    }
    case "select": {
      const values = (payload.value ?? "")
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean);
      if (values.length === 0) {
        throw new Error("select requires one or more comma-separated values");
      }
      request = {
        kind: "select",
        ...target,
        targetId,
        values,
      };
      break;
    }
    default:
      throw new Error(`Unsupported browser action: ${payload.action}`);
  }

  const response = await browserAct(undefined, request, {
    profile: state.profile,
  });
  state.targetId = response.targetId || state.targetId;
  if (response.url?.trim()) {
    state.url = response.url.trim();
  }
  browserSessions.set(state.sessionId, state);
  return await snapshotBrowserSession(state);
}

async function runBrowserDownload(payload: BrowserDownloadRequest) {
  const url = payload.url.trim();
  if (!url) {
    throw new Error("url is required");
  }
  const state = await ensureDefaultBrowserSession(payload.session_id, payload.metadata);
  await openBrowserUrl(state, url);
  const saved = await browserPdfSave(undefined, {
    targetId: state.targetId,
    profile: state.profile,
  });
  let outputPath = saved.path;
  const destination = payload.destination?.trim();
  if (destination) {
    const resolvedDestination = path.resolve(destination);
    await fsp.mkdir(path.dirname(resolvedDestination), { recursive: true });
    await fsp.copyFile(saved.path, resolvedDestination);
    outputPath = resolvedDestination;
  }
  return {
    ok: true as const,
    session_id: state.sessionId,
    url: saved.url ?? state.url ?? url,
    path: outputPath,
  };
}

async function runDocumentRead(payload: DocumentReadRequest) {
  const resolvedPath = path.resolve(payload.path);
  const ext = path.extname(resolvedPath).toLowerCase();
  let text = "";
  if (ext === ".pdf") {
    const buffer = await fsp.readFile(resolvedPath);
    const extracted = await extractPdfContent({
      buffer,
      maxPages: 64,
      maxPixels: 4_000_000,
      minTextChars: 200,
    });
    text = extracted.text.trim();
    if (!text && extracted.images.length > 0) {
      text = `[pdf-image-only] extracted ${extracted.images.length} page images`;
    }
  } else {
    text = await fsp.readFile(resolvedPath, "utf-8");
  }

  return {
    ok: true as const,
    path: resolvedPath,
    sections: buildDocumentSections(text),
  };
}

function buildMcpCapabilityId(toolName: string): string {
  return `mcp_tool:${normalizeToolName(toolName)}`;
}

function normalizeCapabilityLookupKey(capabilityId: string): string {
  const trimmed = capabilityId.trim();
  if (!trimmed) {
    throw new Error("capability_id is required");
  }
  if (trimmed.includes(":")) {
    const [, value] = trimmed.split(/:(.+)/, 2);
    return `mcp_tool:${normalizeToolName(value ?? trimmed)}`;
  }
  return `mcp_tool:${normalizeToolName(trimmed)}`;
}

function parseCapabilityServerName(description: unknown): string | undefined {
  const text = normalizeOptionalString(description);
  if (!text) {
    return undefined;
  }
  const match = text.match(/server "([^"]+)"/i);
  return match?.[1]?.trim();
}

async function disposeBundleMcpState() {
  const current = bundleMcpState;
  bundleMcpState = null;
  if (!current) {
    return;
  }
  await current.runtime?.dispose().catch(() => {});
}

async function hydrateBundleMcpState(params: {
  workspaceDir: string;
  allowedDirs: string[];
  cfg: OpenClawConfig;
  fingerprint: string;
}): Promise<BundleMcpState> {
  if (
    bundleMcpState?.workspaceDir === params.workspaceDir &&
    bundleMcpState.fingerprint === params.fingerprint &&
    bundleMcpState.plugins.length > 0
  ) {
    return bundleMcpState;
  }

  const loadedMcp = loadEmbeddedPiMcpConfig({
    workspaceDir: params.workspaceDir,
    cfg: params.cfg,
  });
  const registeredPlugins = loadRegisteredBundledCapabilityPlugins();
  const serverPluginMap = new Map<string, string>();
  for (const plugin of registeredPlugins) {
    const support = inspectBundleMcpRuntimeSupport({
      pluginId: plugin.pluginId,
      rootDir: plugin.rootDir,
      bundleFormat: "claude",
    });
    for (const serverName of [...support.supportedServerNames, ...support.unsupportedServerNames]) {
      serverPluginMap.set(serverName, plugin.pluginId);
    }
  }

  const plugins: PluginInfo[] = registeredPlugins.map((plugin) => ({
    plugin_id: plugin.pluginId,
    enabled: true,
  }));
  const servers: McpServerInfo[] = Object.keys(loadedMcp.mcpServers)
    .sort((left, right) => left.localeCompare(right))
    .map((serverName) => ({
      server_name: serverName,
      ...(serverPluginMap.get(serverName) ? { plugin_id: serverPluginMap.get(serverName) } : {}),
    }));

  bundleMcpState = {
    workspaceDir: params.workspaceDir,
    allowedDirs: params.allowedDirs,
    fingerprint: params.fingerprint,
    cfg: params.cfg,
    plugins,
    servers,
    runtime: bundleMcpState?.runtime,
    capabilities: bundleMcpState?.capabilities ?? new Map(),
  };
  return bundleMcpState;
}

async function ensureBundleMcpState(
  metadata?: Record<string, string>,
  extraAllowedDirs?: string[],
): Promise<BundleMcpState> {
  const workspaceDir = resolveWorkspaceDir(metadata);
  await fsp.mkdir(workspaceDir, { recursive: true });
  const resolvedConfig = await resolveEmbeddedCapabilityConfig(workspaceDir);
  const allowedDirs = await normalizeBundledCapabilityAllowedDirs(workspaceDir, extraAllowedDirs);
  const mcpConfig = isRecord(resolvedConfig.cfg.mcp) ? resolvedConfig.cfg.mcp : {};
  const cfg: OpenClawConfig = {
    ...resolvedConfig.cfg,
    mcp: {
      ...mcpConfig,
      servers: buildBundledCapabilityMcpServers(workspaceDir, allowedDirs),
    },
  };
  const fingerprint = stableSerialize({
    base: resolvedConfig.fingerprint,
    allowed_dirs: allowedDirs,
  });
  if (
    bundleMcpState?.workspaceDir !== workspaceDir ||
    bundleMcpState.fingerprint !== fingerprint
  ) {
    await disposeBundleMcpState();
  }
  return await hydrateBundleMcpState({
    workspaceDir,
    allowedDirs,
    fingerprint,
    cfg,
  });
}

async function ensureBundleMcpCapabilityState(
  metadata?: Record<string, string>,
  options?: { forceRefresh?: boolean; extraAllowedDirs?: string[] },
): Promise<BundleMcpState> {
  if (options?.forceRefresh) {
    await disposeBundleMcpState();
  }
  const state = await ensureBundleMcpState(metadata, options?.extraAllowedDirs);
  if (state.runtime) {
    return state;
  }

  const runtime = await createBundleMcpToolRuntime({
    workspaceDir: state.workspaceDir,
    cfg: state.cfg,
  });
  const serverPluginMap = new Map(
    state.servers
      .filter((server) => server.plugin_id)
      .map((server) => [server.server_name, server.plugin_id as string]),
  );
  const capabilities = new Map<string, BundleMcpCapabilityState>();
  for (const tool of runtime.tools) {
    const capabilityId = buildMcpCapabilityId(tool.name);
    if (capabilities.has(capabilityId)) {
      continue;
    }
    const hintedServer =
      parseCapabilityServerName(tool.description) ??
      (state.servers.length === 1 ? state.servers[0]?.server_name : undefined);
    const hintedPluginId = hintedServer ? serverPluginMap.get(hintedServer) : undefined;
    capabilities.set(capabilityId, {
      capability: {
        capability_id: capabilityId,
        kind: "mcp_tool",
        ...(hintedPluginId ? { plugin_id: hintedPluginId } : {}),
        ...(hintedServer ? { server_name: hintedServer } : {}),
      },
      tool,
    });
  }

  state.runtime = runtime;
  state.capabilities = capabilities;
  bundleMcpState = state;
  return state;
}

function parseInvokeArgsJson(raw: string | undefined): Record<string, unknown> {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return {};
  }
  const parsed = JSON.parse(trimmed) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("args_json must decode to a JSON object");
  }
  return parsed as Record<string, unknown>;
}

async function runPluginMcpListPlugins(payload: PluginMcpListRequest) {
  const state = await ensureBundleMcpState(payload.metadata);
  return {
    ok: true as const,
    plugins: state.plugins,
  };
}

async function runPluginMcpListServers(payload: PluginMcpListRequest) {
  const state = await ensureBundleMcpState(payload.metadata);
  return {
    ok: true as const,
    servers: state.servers,
  };
}

async function runPluginMcpResolveCapability(payload: PluginMcpResolveRequest) {
  const state = await ensureBundleMcpCapabilityState(payload.metadata);
  return {
    ok: true as const,
    capability: state.capabilities.get(normalizeCapabilityLookupKey(payload.capability_id))
      ?.capability,
  };
}

async function runPluginMcpInvoke(payload: PluginMcpInvokeRequest) {
  const args = parseInvokeArgsJson(payload.args_json);
  const state = await ensureBundleMcpCapabilityState(payload.metadata, {
    extraAllowedDirs: collectBundledCapabilityAllowedDirs(args),
  });
  const capability = state.capabilities.get(normalizeCapabilityLookupKey(payload.capability_id));
  if (!capability) {
    throw new Error(`Unknown MCP capability: ${payload.capability_id}`);
  }
  const result = await capability.tool.execute("qypha-plugin-mcp-invoke", args);
  ensureBundledCapabilityToolSucceeded(capability.capability.capability_id, result);
  return {
    ok: true as const,
    capability_id: capability.capability.capability_id,
    output_json: JSON.stringify(result, null, 2),
  };
}

function looksLikeMcpInventoryQuestion(prompt: string): boolean {
  const normalized = prompt.trim().toLowerCase();
  if (!normalized.includes("mcp")) {
    return false;
  }
  return (
    normalized.includes("server") ||
    normalized.includes("servers") ||
    normalized.includes("tool") ||
    normalized.includes("tools") ||
    normalized.includes("capabilit") ||
    normalized.includes("able to use") ||
    normalized.includes("use now") ||
    normalized.includes("currently have") ||
    normalized.includes("what do you have") ||
    normalized.includes("which do you have")
  );
}

function formatMcpInventoryAnswer(params: {
  configuredServers: McpServerInfo[];
  activeServers: Array<{
    serverName: string;
    toolNames: string[];
  }>;
}): string {
  const configuredNames = params.configuredServers
    .map((entry) => entry.server_name.trim())
    .filter(Boolean);
  const activeServers = params.activeServers
    .map((entry) => ({
      serverName: entry.serverName.trim(),
      toolNames: entry.toolNames.map((tool) => tool.trim()).filter(Boolean),
    }))
    .filter((entry) => entry.serverName.length > 0);
  const activeNames = activeServers.map((entry) => entry.serverName);

  const lines = [
    configuredNames.length > 0
      ? `Bundled/configured MCP servers: ${configuredNames.join(", ")}.`
      : "Bundled/configured MCP servers: none.",
    activeNames.length > 0
      ? `Currently usable in this session: ${activeNames.join(", ")}.`
      : "Currently usable in this session: none.",
  ];

  for (const entry of activeServers) {
    const toolNames = entry.toolNames.slice(0, 16);
    const overflow = entry.toolNames.length - toolNames.length;
    lines.push(
      `- ${entry.serverName}: ${
        toolNames.length > 0 ? toolNames.join(", ") : "no tools exposed"
      }${overflow > 0 ? ` (+${overflow} more)` : ""}`,
    );
  }

  if (configuredNames.length > 0 && activeNames.length === 0) {
    lines.push(
      "The servers are configured, but none of them successfully started in this session yet.",
    );
  }

  return lines.join("\n");
}

async function maybeAnswerMcpInventoryQuestion(
  prompt: string,
  metadata?: Record<string, string>,
): Promise<string | null> {
  if (!looksLikeMcpInventoryQuestion(prompt)) {
    return null;
  }
  const configuredState = await ensureBundleMcpState(metadata);
  const activeState = await ensureBundleMcpCapabilityState(metadata, { forceRefresh: true });
  return formatMcpInventoryAnswer({
    configuredServers: configuredState.servers,
    activeServers: activeState.runtime?.servers ?? [],
  });
}

async function runResearchPlan(payload: ResearchPlanRequest) {
  const provider = normalizeProviderId(payload.provider);
  const modelId = payload.model_id.trim();
  if (!modelId) {
    throw new Error("model_id is required");
  }
  const query = payload.query.trim();
  if (!query) {
    throw new Error("query is required");
  }

  const structured = await generateStructuredResearchJson<{
    disposition?: unknown;
    rationale?: unknown;
    planned_steps?: unknown;
  }>({
    provider,
    model_id: modelId,
    metadata: payload.metadata,
    system_prompt: [
      payload.system_prompt?.trim(),
      "You are Qypha's typed research planner running on the embedded OpenClaw provider runtime.",
      "Return strict JSON only. No prose outside JSON.",
    ]
      .filter(Boolean)
      .join("\n\n"),
    prompt: [
      "Decide whether the assistant should answer directly or investigate further.",
      "Return JSON with exactly these keys:",
      '{ "disposition": "answer_directly|search_web|inspect_specific_sources|use_browser|read_document|inspect_repo", "rationale": "string", "planned_steps": ["step"] }',
      "Rules:",
      "- Use answer_directly only when the answer is stable and does not need external verification.",
      "- Use search_web for current facts, web research, comparisons, and multi-source investigation.",
      "- Use inspect_specific_sources when the user already provided or implied exact URLs/sources to read.",
      "- Use use_browser when rendering, login, or JS-heavy navigation matters.",
      "- Use read_document when the primary source is a PDF, paper, standards document, technical report, or long document.",
      "- Literature reviews, paper comparisons, arXiv/DOI questions, and methodology/results questions should bias strongly toward read_document.",
      "- Use inspect_repo when the question is about code, repositories, GitHub contents, or local project files.",
      "- If a stronger primary-source path exists, do not choose answer_directly.",
      `User query: ${query}`,
      `Current answer draft: ${payload.current_answer_draft?.trim() || "none"}`,
      `Local context available: ${payload.local_context_available ? "yes" : "no"}`,
    ].join("\n"),
  });

  const plannedSteps = Array.isArray(structured.planned_steps)
    ? structured.planned_steps
        .map((value) => normalizeOptionalString(value))
        .filter((value): value is string => Boolean(value))
    : [];

  return {
    ok: true as const,
    disposition: normalizeResearchDisposition(structured.disposition),
    rationale:
      normalizeOptionalString(structured.rationale) ??
      "Model did not provide a rationale for the research decision.",
    planned_steps: plannedSteps,
  };
}

async function runResearchSearch(payload: ResearchSearchRequest) {
  const provider = normalizeProviderId(payload.provider);
  const modelId = payload.model_id.trim();
  const baseQuery = payload.query.trim();
  const scope = normalizeResearchSourceScope(payload.scope);
  if (!modelId) {
    throw new Error("model_id is required");
  }
  if (!baseQuery) {
    throw new Error("query is required");
  }
  const query = [
    baseQuery,
    payload.technical_only ? "technical documentation primary sources" : "",
    payload.recency_required ? "latest current" : "",
  ]
    .filter(Boolean)
    .join(" ")
    .trim();
  if (scope?.allow_open_web === false && (scope.allowed_domains?.length ?? 0) === 0) {
    return {
      ok: true as const,
      query,
      sources: [],
      action_log: [
        createResearchActionLogEntry({
          action: "search",
          query,
          note: "Research scope blocked open-web search because no allowed domains were provided.",
        }),
      ],
    };
  }

  const searchTool = createWebSearchTool({
    config: buildEmbeddedRuntimeConfig(provider, modelId, payload.metadata),
    runtimeWebSearch: undefined,
  });
  if (!searchTool?.execute) {
    throw new Error("web_search tool is unavailable in the embedded OpenClaw runtime");
  }
  const requestedMaxResults = Math.max(1, Math.min(10, Math.floor(payload.max_results ?? 8)));

  const rawResult = await searchTool.execute("qypha-research-search", {
    query,
    maxResults: requestedMaxResults,
  });
  const details =
    rawResult.details && typeof rawResult.details === "object" && !Array.isArray(rawResult.details)
      ? (rawResult.details as Record<string, unknown>)
      : {};
  const results = Array.isArray(details.results) ? details.results : [];
  const sources = applyResearchSourceScope(
    results
      .slice(0, requestedMaxResults)
      .map((entry) => normalizeResearchSource(entry))
      .filter((entry): entry is ResearchSource => Boolean(entry)),
    scope,
  ).slice(0, requestedMaxResults);

  return {
    ok: true as const,
    query,
    sources,
    action_log: [
      createResearchActionLogEntry({
        action: "search",
        query,
        note: `Returned ${sources.length} source(s) after scope filtering.`,
      }),
    ],
  };
}

async function runResearchInspect(payload: ResearchInspectRequest) {
  const provider = normalizeProviderId(payload.provider);
  const modelId = payload.model_id.trim();
  const query = payload.query.trim();
  const scope = normalizeResearchSourceScope(payload.scope);
  if (!modelId) {
    throw new Error("model_id is required");
  }
  if (!query) {
    throw new Error("query is required");
  }

  const fetchTool = createWebFetchTool({
    config: buildEmbeddedRuntimeConfig(provider, modelId, payload.metadata),
  });
  if (!fetchTool || typeof fetchTool.execute !== "function") {
    throw new Error("web_fetch tool is unavailable in the embedded OpenClaw runtime");
  }

  const inspectedSources: InspectedResearchSource[] = [];
  const consultedSources: ConsultedSourceRecord[] = [];
  const actionLog: ResearchActionLogEntry[] = [];
  const maxSources = inferInspectBudget(payload);
  const scopedSources = applyResearchSourceScope(payload.sources, scope).slice(0, maxSources);
  if (scopedSources.length === 0) {
    return {
      ok: true as const,
      query,
      inspected_sources: [],
      consulted_sources: [],
      action_log: [
        createResearchActionLogEntry({
          action: "inspect_source",
          query,
          note: "No sources remained after applying the current research scope.",
        }),
      ],
    };
  }
  const inspectSessionPrefix =
    resolveMetadataString(payload.metadata, "session_id") ?? sanitizeIdentifier(query).slice(0, 24);
  for (const [index, source] of scopedSources.entries()) {
    const maxChars = inferInspectMaxChars(query, source);
    const fetchedInspection = await fetchResearchInspectionContent({
      fetchTool,
      source,
      query,
      maxChars,
    });
    const extractedText = fetchedInspection.plainText;
    const extractor = fetchedInspection.extractor;
    const warning = fetchedInspection.warning;
    const contentType = fetchedInspection.contentType;
    const notes = fetchedInspection.notes;
    const fetchConsultedSource = buildConsultedSourceRecord({
      source,
      extractionMode: extractor,
      content: fetchedInspection.displayText,
      headings: fetchedInspection.headings,
      notes,
    });
    consultedSources.push(fetchConsultedSource);
    actionLog.push(
      createResearchActionLogEntry({
        action: "inspect_source",
        url: source.url,
        note: `Fetch extracted ${fetchConsultedSource.content_length_chars} chars via ${fetchConsultedSource.extraction_mode}.`,
      }),
    );

    let finalText = fetchedInspection.displayText;
    let finalNotes = notes;
    let preferredConsultedSource = fetchConsultedSource;
    const browserDecision = shouldEscalateInspectToBrowser({
      source,
      query,
      extractedText,
      extractor,
      warning,
      contentType,
    });

    if (browserDecision.escalate) {
      const browserSessionId = `inspect-${sanitizeIdentifier(inspectSessionPrefix)}-${index + 1}`;
      try {
        const browserInspection = await inspectSourceViaBrowser({
          sessionId: browserSessionId,
          source,
          query,
          scope,
          metadata: payload.metadata,
          escalationReason:
            browserDecision.reason ?? "Browser escalation was requested by inspection policy.",
        });
        consultedSources.push(browserInspection.consultedSource);
        actionLog.push(...browserInspection.actionLog);
        if (
          shouldPreferBrowserInspection({
            fetchText: extractedText,
            query,
            browserMarkdown: browserInspection.markdown,
            browserMatches: browserInspection.matches,
          })
        ) {
          finalText = browserInspection.markdown;
          finalNotes = [
            finalNotes,
            `browser_escalation:${browserDecision.reason ?? "inspection policy"}`,
            browserInspection.consultedSource.notes,
          ]
            .filter(Boolean)
            .join(" | ");
          preferredConsultedSource = browserInspection.consultedSource;
        } else {
          finalNotes = [
            finalNotes,
            `browser_checked:${browserDecision.reason ?? "inspection policy"}`,
          ]
            .filter(Boolean)
            .join(" | ");
        }
      } catch (error) {
        actionLog.push(
          createResearchActionLogEntry({
            action: "open_page_failed",
            url: source.url,
            note: `Browser escalation failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          }),
        );
        finalNotes = [
          finalNotes,
          `browser_escalation_failed:${error instanceof Error ? error.message : String(error)}`,
        ]
          .filter(Boolean)
          .join(" | ");
      }
    }

    if (
      shouldAttemptLinkedDocumentFollowUp({
        source,
        query,
        linkCandidates: fetchedInspection.linkCandidates,
        extractedText,
      })
    ) {
      const followUpBudget = inferLinkedDocumentFollowUpBudget(query);
      const followUpCandidates = fetchedInspection.linkCandidates.slice(0, followUpBudget);
      for (const [candidateIndex, candidate] of followUpCandidates.entries()) {
        actionLog.push(
          createResearchActionLogEntry({
            action: "follow_linked_document",
            url: candidate.source.url,
            note: `Following linked document candidate "${candidate.label}" (${candidate.rationale}).`,
          }),
        );
        try {
          const followUpMaxChars = Math.max(maxChars, inferInspectMaxChars(query, candidate.source));
          const followUpFetch = await fetchResearchInspectionContent({
            fetchTool,
            source: candidate.source,
            query,
            maxChars: followUpMaxChars,
          });
          let followUpText = followUpFetch.displayText;
          let followUpNotes = [
            `linked_document:${candidate.rationale}`,
            followUpFetch.notes,
          ]
            .filter(Boolean)
            .join(" | ");
          let followUpConsultedSource = buildConsultedSourceRecord({
            source: candidate.source,
            extractionMode: followUpFetch.extractor,
            content: followUpText,
            headings: followUpFetch.headings,
            notes: followUpNotes,
          });
          consultedSources.push(followUpConsultedSource);
          actionLog.push(
            createResearchActionLogEntry({
              action: "inspect_source",
              url: candidate.source.url,
              note: `Linked document extracted ${followUpConsultedSource.content_length_chars} chars via ${followUpConsultedSource.extraction_mode}.`,
            }),
          );

          const followUpBrowserDecision = shouldEscalateInspectToBrowser({
            source: candidate.source,
            query,
            extractedText: followUpFetch.plainText,
            extractor: followUpFetch.extractor,
            warning: followUpFetch.warning,
            contentType: followUpFetch.contentType,
          });

          if (followUpBrowserDecision.escalate) {
            const browserSessionId = `follow-${sanitizeIdentifier(inspectSessionPrefix)}-${index + 1}-${candidateIndex + 1}`;
            try {
              const browserInspection = await inspectSourceViaBrowser({
                sessionId: browserSessionId,
                source: candidate.source,
                query,
                scope,
                metadata: payload.metadata,
                escalationReason:
                  followUpBrowserDecision.reason ??
                  "Browser escalation was requested by linked-document inspection policy.",
              });
              consultedSources.push(browserInspection.consultedSource);
              actionLog.push(...browserInspection.actionLog);
              if (
                shouldPreferBrowserInspection({
                  fetchText: followUpFetch.plainText,
                  query,
                  browserMarkdown: browserInspection.markdown,
                  browserMatches: browserInspection.matches,
                })
              ) {
                followUpText = browserInspection.markdown;
                followUpNotes = [
                  followUpNotes,
                  `browser_escalation:${followUpBrowserDecision.reason ?? "linked document inspection policy"}`,
                  browserInspection.consultedSource.notes,
                ]
                  .filter(Boolean)
                  .join(" | ");
                followUpConsultedSource = browserInspection.consultedSource;
              } else {
                followUpNotes = [
                  followUpNotes,
                  `browser_checked:${followUpBrowserDecision.reason ?? "linked document inspection policy"}`,
                ]
                  .filter(Boolean)
                  .join(" | ");
              }
            } catch (error) {
              actionLog.push(
                createResearchActionLogEntry({
                  action: "open_page_failed",
                  url: candidate.source.url,
                  note: `Linked document browser escalation failed: ${
                    error instanceof Error ? error.message : String(error)
                  }`,
                }),
              );
              followUpNotes = [
                followUpNotes,
                `browser_escalation_failed:${error instanceof Error ? error.message : String(error)}`,
              ]
                .filter(Boolean)
                .join(" | ");
            }
          }

          if (shouldAppendLinkedDocument({ query, candidate })) {
            const combined = combineInspectionTexts({
              baseText: finalText,
              linkedTitle: candidate.label,
              linkedText: followUpText,
              maxChars: Math.max(maxChars, 70_000),
            });
            finalText = combined.text;
            finalNotes = [
              finalNotes,
              `linked_document_appended:${candidate.rationale}`,
              combined.truncated ? "linked_document_truncated" : undefined,
              followUpNotes,
            ]
              .filter(Boolean)
              .join(" | ");
            preferredConsultedSource = followUpConsultedSource;
            break;
          }

          if (
            shouldPreferLinkedDocument({
              currentSource: source,
              currentText: finalText,
              query,
              candidate,
              followUpText,
            })
          ) {
            finalText = followUpText;
            finalNotes = [finalNotes, `linked_document_preferred:${candidate.rationale}`, followUpNotes]
              .filter(Boolean)
              .join(" | ");
            preferredConsultedSource = followUpConsultedSource;
            break;
          }

          finalNotes = [finalNotes, `linked_document_checked:${candidate.rationale}`]
            .filter(Boolean)
            .join(" | ");
        } catch (error) {
          actionLog.push(
            createResearchActionLogEntry({
              action: "follow_linked_document_failed",
              url: candidate.source.url,
              note: error instanceof Error ? error.message : String(error),
            }),
          );
          finalNotes = [
            finalNotes,
            `linked_document_failed:${error instanceof Error ? error.message : String(error)}`,
          ]
            .filter(Boolean)
            .join(" | ");
        }
      }
    }

    inspectedSources.push({
      source,
      extracted_text: finalText,
      ...(finalNotes ? { notes: finalNotes } : {}),
      disagreement_flags: [],
      consulted_source: preferredConsultedSource,
    });
  }

  return {
    ok: true as const,
    query,
    inspected_sources: inspectedSources,
    consulted_sources: consultedSources,
    action_log: actionLog,
  };
}

async function runResearchOpenPage(payload: ResearchOpenPageRequest) {
  const source = normalizeResearchSource(payload.source);
  if (!source) {
    throw new Error("source.url is required for research_open_page");
  }
  const state = await ensureResearchBrowserSession(
    payload.session_id,
    payload.scope,
    payload.metadata,
  );
  await openBrowserUrl(state, source.url);
  const snapshot = await snapshotBrowserSession(state);
  const markdown = snapshot.markdown ?? "";
  const consultedSource = buildConsultedSourceRecord({
    source,
    extractionMode: "browser_snapshot_ai",
    content: markdown,
    headings: extractMarkdownHeadings(markdown),
    notes: "Opened via typed research_open_page.",
  });

  return {
    ok: true as const,
    session_id: snapshot.session_id,
    url: snapshot.url ?? source.url,
    markdown,
    consulted_source: consultedSource,
    action_log: [
      createResearchActionLogEntry({
        action: "open_page",
        url: source.url,
        session_id: snapshot.session_id,
        note: "Opened source in the embedded browser and captured an AI snapshot.",
      }),
    ],
  };
}

async function runResearchFindInPage(payload: ResearchFindInPageRequest) {
  const query = payload.query.trim();
  if (!query) {
    throw new Error("query is required");
  }

  const source = payload.source ? normalizeResearchSource(payload.source) : null;
  const targetUrl = normalizeOptionalString(payload.url) ?? source?.url;
  const state = await ensureResearchBrowserSession(
    payload.session_id,
    payload.scope,
    payload.metadata,
  );
  const actionLog: ResearchActionLogEntry[] = [];
  if (targetUrl) {
    await openBrowserUrl(state, targetUrl);
    actionLog.push(
      createResearchActionLogEntry({
        action: "open_page",
        url: targetUrl,
        session_id: state.sessionId,
        note: "Opened page before running typed in-page search.",
      }),
    );
  }

  const snapshot = await snapshotBrowserSession(state);
  const markdown = snapshot.markdown ?? "";
  const matches = findMatchesInMarkdown(
    markdown,
    query,
    Math.max(1, Math.min(25, Math.floor(payload.max_matches ?? 8))),
  );
  actionLog.push(
    createResearchActionLogEntry({
      action: "find_in_page",
      url: snapshot.url,
      session_id: snapshot.session_id,
      query,
      note: `Found ${matches.length} matching line(s) in the current browser snapshot.`,
    }),
  );

  const effectiveSource =
    source ??
    normalizeResearchSource({
      title: snapshot.url ?? "Current browser page",
      url: snapshot.url ?? targetUrl ?? "",
      source_kind: "web",
    });
  const consultedSource =
    effectiveSource && (snapshot.url?.trim() || targetUrl?.trim())
      ? buildConsultedSourceRecord({
          source: effectiveSource,
          extractionMode: "browser_find_in_page",
          content: markdown,
          headings: extractMarkdownHeadings(markdown),
          findQueries: [query],
          notes:
            matches.length > 0
              ? "Matched content was found in the current browser snapshot."
              : "No direct matches were found in the current browser snapshot.",
        })
      : undefined;

  return {
    ok: true as const,
    session_id: snapshot.session_id,
    url: snapshot.url ?? targetUrl ?? "",
    query,
    matches,
    ...(consultedSource ? { consulted_source: consultedSource } : {}),
    action_log: actionLog,
  };
}

async function runResearchSynthesize(payload: ResearchSynthesizeRequest) {
  const provider = normalizeProviderId(payload.provider);
  const modelId = payload.model_id.trim();
  const query = payload.query.trim();
  if (!modelId) {
    throw new Error("model_id is required");
  }
  if (!query) {
    throw new Error("query is required");
  }

  const structured = await generateStructuredResearchJson<{
    answer?: unknown;
    uncertainty?: unknown;
    citations?: unknown;
  }>({
    provider,
    model_id: modelId,
    metadata: payload.metadata,
    system_prompt: [
      payload.system_prompt?.trim(),
      "You are Qypha's typed research synthesis step on the embedded OpenClaw runtime.",
      "Return strict JSON only. No prose outside JSON.",
    ]
      .filter(Boolean)
      .join("\n\n"),
    prompt: [
      "Synthesize the research material into a concise answer.",
      "Return JSON with exactly these keys:",
      '{ "answer": "string", "uncertainty": "string", "citations": ["url"] }',
      "If the evidence is strong, uncertainty can be an empty string.",
      `Desired format: ${payload.desired_format?.trim() || "concise answer with citations"}`,
      `User query: ${query}`,
      `Sources JSON: ${JSON.stringify(payload.sources ?? [], null, 2)}`,
      `Inspected sources JSON: ${JSON.stringify(payload.inspected_sources ?? [], null, 2)}`,
    ].join("\n\n"),
  });

  const citations = Array.isArray(structured.citations)
    ? structured.citations
        .map((value) => normalizeOptionalString(value))
        .filter((value): value is string => Boolean(value))
    : [];
  const fallbackCitations =
    citations.length > 0
      ? citations
      : (payload.inspected_sources ?? [])
          .map((entry) => normalizeOptionalString(entry.source?.url))
          .filter((value): value is string => Boolean(value));
  const sourcesUsed =
    (payload.consulted_sources ?? []).length > 0
      ? Array.from(
          new Map(
            (payload.consulted_sources ?? []).map((entry) => [
              `${entry.source.url}::${entry.extraction_mode}::${entry.accessed_at_ms}`,
              entry,
            ]),
          ).values(),
        )
      : (payload.inspected_sources ?? [])
          .map((entry) => entry.consulted_source)
          .filter((value): value is ConsultedSourceRecord => Boolean(value));

  return {
    ok: true as const,
    answer:
      normalizeOptionalString(structured.answer) ?? "Model did not provide a synthesized answer.",
    ...(normalizeOptionalString(structured.uncertainty)
      ? { uncertainty: normalizeOptionalString(structured.uncertainty) }
      : {}),
    citations: fallbackCitations,
    sources_used: sourcesUsed,
  };
}

let embeddedRunnerImport:
  | Promise<typeof import("../src/agents/pi-embedded-runner/run.js")>
  | undefined;

async function loadEmbeddedRunner() {
  embeddedRunnerImport ??= import("../src/agents/pi-embedded-runner/run.js");
  return await embeddedRunnerImport;
}

async function runWithEmbeddedAgent(payload: AgentRunRequest) {
  debugLog("agent_run:start");
  const provider = normalizeProviderId(payload.provider);
  const modelId = payload.model_id.trim();
  if (!modelId) {
    throw new Error("model_id is required");
  }
  const prompt = payload.prompt.trim();
  if (!prompt) {
    throw new Error("prompt is required");
  }

  const metadata = payload.metadata;
  const actor = resolveEmbeddedActorContext({
    actorId: resolveMetadataString(metadata, "agent_name"),
    metadata,
  });
  const agentDir =
    resolveMetadataString(metadata, "agent_dir") ??
    resolveEmbeddedActorDir({
      actorId: actor.agentId,
      metadata,
    });
  const sessionFile =
    resolveMetadataString(metadata, "session_file") ??
    path.join(agentDir, "sessions", "self.session.json");
  const workspaceDir = resolveWorkspaceDir(metadata, actor.actorId);
  const sessionId =
    resolveMetadataString(metadata, "session_id") ?? `qypha-${Date.now().toString(36)}`;
  const timeoutMsRaw = Number(resolveMetadataString(metadata, "timeout_ms") ?? "180000");
  const timeoutMs =
    Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0 ? Math.floor(timeoutMsRaw) : 180_000;

  fs.mkdirSync(agentDir, { recursive: true });
  fs.mkdirSync(path.dirname(sessionFile), { recursive: true });
  fs.mkdirSync(workspaceDir, { recursive: true });
  debugLog(`agent_run:prepared provider=${provider} model=${modelId} session=${sessionId}`);

  const mcpInventoryAnswer = await maybeAnswerMcpInventoryQuestion(prompt, metadata);
  if (mcpInventoryAnswer) {
    debugLog(`agent_run:answered_mcp_inventory session=${sessionId}`);
    return {
      ok: true as const,
      model_id: modelId,
      output_text: mcpInventoryAnswer,
      finish_reason: "stop",
    };
  }

  let researchExecutionPolicy: string | null = null;
  if (shouldRunResearchPlannerForPrompt(prompt)) {
    try {
      const plannerResult = await runResearchPlan({
        provider,
        model_id: modelId,
        query: prompt,
        current_answer_draft: null,
        local_context_available: true,
        system_prompt: payload.system_prompt ?? undefined,
        metadata,
      });
      const mergedPlan = mergeResearchDisposition({
        prompt,
        modelDisposition: plannerResult.disposition,
      });
      const finalSteps =
        plannerResult.planned_steps.length > 0
          ? plannerResult.planned_steps
          : defaultPlannedStepsForDisposition(mergedPlan.disposition, prompt);
      const rationale =
        mergedPlan.disposition !== plannerResult.disposition && mergedPlan.heuristicRationale
          ? `${plannerResult.rationale} Heuristic override: ${mergedPlan.heuristicRationale}`
          : plannerResult.rationale;
      researchExecutionPolicy = buildResearchExecutionPolicy({
        prompt,
        disposition: mergedPlan.disposition,
        rationale,
        plannedSteps: finalSteps,
      });
      debugLog(
        `agent_run:research_plan disposition=${mergedPlan.disposition} session=${sessionId}`,
      );
    } catch (error) {
      const heuristicPlan = mergeResearchDisposition({
        prompt,
      });
      researchExecutionPolicy = buildResearchExecutionPolicy({
        prompt,
        disposition: heuristicPlan.disposition,
        rationale:
          heuristicPlan.heuristicRationale ??
          "Research planner was unavailable; applying Qypha heuristic execution policy.",
        plannedSteps: defaultPlannedStepsForDisposition(heuristicPlan.disposition, prompt),
      });
      debugLog(
        `agent_run:research_plan_fallback disposition=${heuristicPlan.disposition} error=${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  const { runEmbeddedPiAgent } = await loadEmbeddedRunner();
  debugLog("agent_run:runner_loaded");

  let result;
  const previousDisableImplicitProviders =
    process.env.QYPHA_EMBEDDED_DISABLE_IMPLICIT_PROVIDERS;
  const previousSkipSandbox = process.env.QYPHA_EMBEDDED_SKIP_SANDBOX;
  const previousQyphaControlSocket = process.env.QYPHA_COMPANION_CONTROL_SOCKET;
  const previousQyphaControlToken = process.env.QYPHA_COMPANION_CONTROL_TOKEN;
  const previousQyphaRequester = process.env.QYPHA_COMPANION_REQUESTER_AGENT;
  const previousQyphaReceiveDirDefault = process.env.QYPHA_RECEIVE_DIR_DEFAULT;
  const previousQyphaReceiveDirGlobal = process.env.QYPHA_RECEIVE_DIR_GLOBAL;
  const previousQyphaReceiveDirEffective = process.env.QYPHA_RECEIVE_DIR_EFFECTIVE;
  const previousQyphaReceiveDirSource = process.env.QYPHA_RECEIVE_DIR_SOURCE;
  const previousWorkspaceDir = process.env.QYPHA_RUNTIME_WORKSPACE_DIR;
  const embeddedConfig = buildEmbeddedRunConfig(provider, modelId, metadata);
  try {
    process.env.QYPHA_EMBEDDED_DISABLE_IMPLICIT_PROVIDERS = "1";
    process.env.QYPHA_EMBEDDED_SKIP_SANDBOX = "1";
    const quietLinkControlSocket =
      resolveMetadataString(metadata, "qypha_companion_control_socket") ?? "";
    const quietLinkControlToken =
      resolveMetadataString(metadata, "qypha_companion_control_token") ?? "";
    const quietLinkRequester = resolveMetadataString(metadata, "requester_agent") ?? "self";
    const quietLinkReceiveDirDefault =
      resolveMetadataString(metadata, "qypha_receive_dir_default") ?? "";
    const quietLinkReceiveDirGlobal =
      resolveMetadataString(metadata, "qypha_receive_dir_global") ?? "";
    const quietLinkReceiveDirEffective =
      resolveMetadataString(metadata, "qypha_receive_dir_effective") ?? "";
    const quietLinkReceiveDirSource =
      resolveMetadataString(metadata, "qypha_receive_dir_source") ?? "";
    const runtimeWorkspaceDir = resolveMetadataString(metadata, "workspace_dir") ?? workspaceDir;
    if (quietLinkControlSocket) {
      process.env.QYPHA_COMPANION_CONTROL_SOCKET = quietLinkControlSocket;
    } else {
      delete process.env.QYPHA_COMPANION_CONTROL_SOCKET;
    }
    if (quietLinkControlToken) {
      process.env.QYPHA_COMPANION_CONTROL_TOKEN = quietLinkControlToken;
    } else {
      delete process.env.QYPHA_COMPANION_CONTROL_TOKEN;
    }
    process.env.QYPHA_COMPANION_REQUESTER_AGENT = quietLinkRequester;
    if (quietLinkReceiveDirDefault) {
      process.env.QYPHA_RECEIVE_DIR_DEFAULT = quietLinkReceiveDirDefault;
    } else {
      delete process.env.QYPHA_RECEIVE_DIR_DEFAULT;
    }
    if (quietLinkReceiveDirGlobal) {
      process.env.QYPHA_RECEIVE_DIR_GLOBAL = quietLinkReceiveDirGlobal;
    } else {
      delete process.env.QYPHA_RECEIVE_DIR_GLOBAL;
    }
    if (quietLinkReceiveDirEffective) {
      process.env.QYPHA_RECEIVE_DIR_EFFECTIVE = quietLinkReceiveDirEffective;
    } else {
      delete process.env.QYPHA_RECEIVE_DIR_EFFECTIVE;
    }
    if (quietLinkReceiveDirSource) {
      process.env.QYPHA_RECEIVE_DIR_SOURCE = quietLinkReceiveDirSource;
    } else {
      delete process.env.QYPHA_RECEIVE_DIR_SOURCE;
    }
    process.env.QYPHA_RUNTIME_WORKSPACE_DIR = runtimeWorkspaceDir;
    result = await runEmbeddedPiAgent({
      sessionId,
      sessionKey: sessionId,
      agentId: actor.agentId,
      trigger: "user",
      sessionFile,
      workspaceDir,
      agentDir,
      config: embeddedConfig as never,
      prompt,
      provider,
      model: modelId,
      timeoutMs,
      runId: `qypha-run-${Date.now().toString(36)}`,
      disableMessageTool: true,
      requireExplicitMessageTarget: true,
      senderIsOwner: true,
      bootstrapContextMode: "lightweight",
      enqueue: async (task) => await task(),
      execOverrides: {
        host: "gateway",
        security: "full",
        ask: "off",
      },
      extraSystemPrompt:
        [payload.system_prompt?.trim(), researchExecutionPolicy].filter(Boolean).join("\n\n") ||
        undefined,
    });
  } catch (error) {
    const details = error instanceof Error ? (error.stack ?? error.message) : String(error);
    debugLog(`agent_run:error ${details}`);
    throw error;
  } finally {
    if (previousDisableImplicitProviders === undefined) {
      delete process.env.QYPHA_EMBEDDED_DISABLE_IMPLICIT_PROVIDERS;
    } else {
      process.env.QYPHA_EMBEDDED_DISABLE_IMPLICIT_PROVIDERS = previousDisableImplicitProviders;
    }
    if (previousSkipSandbox === undefined) {
      delete process.env.QYPHA_EMBEDDED_SKIP_SANDBOX;
    } else {
      process.env.QYPHA_EMBEDDED_SKIP_SANDBOX = previousSkipSandbox;
    }
    if (previousQyphaControlSocket === undefined) {
      delete process.env.QYPHA_COMPANION_CONTROL_SOCKET;
    } else {
      process.env.QYPHA_COMPANION_CONTROL_SOCKET = previousQyphaControlSocket;
    }
    if (previousQyphaControlToken === undefined) {
      delete process.env.QYPHA_COMPANION_CONTROL_TOKEN;
    } else {
      process.env.QYPHA_COMPANION_CONTROL_TOKEN = previousQyphaControlToken;
    }
    if (previousQyphaRequester === undefined) {
      delete process.env.QYPHA_COMPANION_REQUESTER_AGENT;
    } else {
      process.env.QYPHA_COMPANION_REQUESTER_AGENT = previousQyphaRequester;
    }
    if (previousQyphaReceiveDirDefault === undefined) {
      delete process.env.QYPHA_RECEIVE_DIR_DEFAULT;
    } else {
      process.env.QYPHA_RECEIVE_DIR_DEFAULT = previousQyphaReceiveDirDefault;
    }
    if (previousQyphaReceiveDirGlobal === undefined) {
      delete process.env.QYPHA_RECEIVE_DIR_GLOBAL;
    } else {
      process.env.QYPHA_RECEIVE_DIR_GLOBAL = previousQyphaReceiveDirGlobal;
    }
    if (previousQyphaReceiveDirEffective === undefined) {
      delete process.env.QYPHA_RECEIVE_DIR_EFFECTIVE;
    } else {
      process.env.QYPHA_RECEIVE_DIR_EFFECTIVE = previousQyphaReceiveDirEffective;
    }
    if (previousQyphaReceiveDirSource === undefined) {
      delete process.env.QYPHA_RECEIVE_DIR_SOURCE;
    } else {
      process.env.QYPHA_RECEIVE_DIR_SOURCE = previousQyphaReceiveDirSource;
    }
    if (previousWorkspaceDir === undefined) {
      delete process.env.QYPHA_RUNTIME_WORKSPACE_DIR;
    } else {
      process.env.QYPHA_RUNTIME_WORKSPACE_DIR = previousWorkspaceDir;
    }
  }
  debugLog(`agent_run:completed stop_reason=${result.meta.stopReason ?? "unknown"}`);

  const outputText = extractPayloadText(result.payloads);
  if (!outputText) {
    if (result.meta.error?.message) {
      throw new Error(result.meta.error.message);
    }
    throw new Error(
      `Embedded agent ${provider}/${modelId} completed without a final text response`,
    );
  }

  return {
    ok: true as const,
    model_id: modelId,
    output_text: outputText,
    finish_reason: result.meta.stopReason,
  };
}

async function handleRequest(request: WorkerRequest): Promise<WorkerSuccess> {
  if (request.op === "hello") {
    return {
      ok: true,
      worker: "qypha-embedded-runtime",
      version: 1,
      capabilities: CAPABILITIES,
    };
  }
  if (request.op === "provider_healthcheck") {
    return await runProviderHealthcheck(request.payload);
  }
  if (request.op === "provider_list_models") {
    return await runProviderListModels(request.payload);
  }
  if (request.op === "provider_generate") {
    return await generateWithProvider(request.payload);
  }
  if (request.op === "memory_get") {
    return await runMemoryGet(request.payload);
  }
  if (request.op === "memory_write") {
    return await runMemoryWrite(request.payload);
  }
  if (request.op === "memory_search") {
    return await runMemorySearch(request.payload);
  }
  if (request.op === "memory_compress") {
    return await runMemoryCompress(request.payload);
  }
  if (request.op === "memory_staleness_check") {
    return await runMemoryStalenessCheck(request.payload);
  }
  if (request.op === "repo_overview") {
    return await runRepoOverview(request.payload);
  }
  if (request.op === "repo_tree") {
    return await runRepoTree(request.payload);
  }
  if (request.op === "repo_grep") {
    return await runRepoGrep(request.payload);
  }
  if (request.op === "repo_read_file") {
    return await runRepoReadFile(request.payload);
  }
  if (request.op === "repo_git_log") {
    return await runRepoGitLog(request.payload);
  }
  if (request.op === "repo_remote_inspect") {
    return await runRepoRemoteInspect(request.payload);
  }
  if (request.op === "os_execute") {
    return await runOsExecute(request.payload);
  }
  if (request.op === "agent_run") {
    return await runWithEmbeddedAgent(request.payload);
  }
  if (request.op === "research_plan") {
    return await runResearchPlan(request.payload);
  }
  if (request.op === "research_search") {
    return await runResearchSearch(request.payload);
  }
  if (request.op === "research_inspect") {
    return await runResearchInspect(request.payload);
  }
  if (request.op === "research_open_page") {
    return await runResearchOpenPage(request.payload);
  }
  if (request.op === "research_find_in_page") {
    return await runResearchFindInPage(request.payload);
  }
  if (request.op === "research_synthesize") {
    return await runResearchSynthesize(request.payload);
  }
  if (request.op === "browser_start_session") {
    return await runBrowserStartSession(request.payload);
  }
  if (request.op === "browser_open") {
    return await runBrowserOpen(request.payload);
  }
  if (request.op === "browser_snapshot") {
    return await runBrowserSnapshot(request.payload);
  }
  if (request.op === "browser_interact") {
    return await runBrowserInteract(request.payload);
  }
  if (request.op === "browser_download") {
    return await runBrowserDownload(request.payload);
  }
  if (request.op === "document_read") {
    return await runDocumentRead(request.payload);
  }
  if (request.op === "plugin_mcp_list_plugins") {
    return await runPluginMcpListPlugins(request.payload);
  }
  if (request.op === "plugin_mcp_list_servers") {
    return await runPluginMcpListServers(request.payload);
  }
  if (request.op === "plugin_mcp_resolve_capability") {
    return await runPluginMcpResolveCapability(request.payload);
  }
  if (request.op === "plugin_mcp_invoke") {
    return await runPluginMcpInvoke(request.payload);
  }
  throw new Error("Unsupported worker operation");
}

async function writeWorkerResponse(response: WorkerSuccess | WorkerFailure) {
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(response)}\n`, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function* readStdinLines(): AsyncGenerator<string> {
  debugLog("worker:read_stdin:start");
  const reader = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  });
  for await (const line of reader) {
    const raw = line.trim();
    if (!raw) {
      continue;
    }
    debugLog(`worker:read_stdin:line bytes=${raw.length}`);
    yield raw;
  }
  debugLog("worker:read_stdin:eof");
}

void (async () => {
  try {
    debugLog("worker:main:start");
    for await (const raw of readStdinLines()) {
      try {
        const request = JSON.parse(raw) as WorkerRequest;
        debugLog(`worker:main:request op=${request.op}`);
        const result = await handleRequest(request);
        debugLog("worker:main:handled");
        await writeWorkerResponse(result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const details = error instanceof Error ? (error.stack ?? error.message) : String(error);
        debugLog(`worker:main:request_error ${details}`);
        const failure: WorkerFailure = {
          ok: false,
          error: message,
        };
        await writeWorkerResponse(failure);
      }
    }
    debugLog("worker:main:exit");
    process.exit(0);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const details = error instanceof Error ? (error.stack ?? error.message) : String(error);
    debugLog(`worker:main:error ${details}`);
    const failure: WorkerFailure = {
      ok: false,
      error: message,
    };
    try {
      await writeWorkerResponse(failure);
    } finally {
      process.exit(1);
    }
  }
})();

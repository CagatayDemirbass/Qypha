import { createHmac, createHash } from "node:crypto";
import type { ReasoningLevel, ThinkLevel } from "../auto-reply/thinking.js";
import { SILENT_REPLY_TOKEN } from "../auto-reply/tokens.js";
import type { MemoryCitationsMode } from "../config/types.memory.js";
import { buildMemoryPromptSection } from "../memory/prompt-section.js";
import { listDeliverableMessageChannels } from "../utils/message-channel.js";
import type { ResolvedTimeFormat } from "./date-time.js";
import type { EmbeddedContextFile } from "./pi-embedded-helpers.js";
import type { EmbeddedSandboxInfo } from "./pi-embedded-runner/types.js";
import { sanitizeForPromptLiteral } from "./sanitize-for-prompt.js";

/**
 * Controls which hardcoded sections are included in the system prompt.
 * - "full": All sections (default, for main agent)
 * - "minimal": Reduced sections (Tooling, Workspace, Runtime) - used for subagents
 * - "none": Just basic identity line, no sections
 */
export type PromptMode = "full" | "minimal" | "none";
type OwnerIdDisplay = "raw" | "hash";

type RuntimeMcpServerInfo = {
  serverName: string;
  toolNames?: string[];
};

function buildSkillsSection(params: { skillsPrompt?: string; readToolName: string }) {
  const trimmed = params.skillsPrompt?.trim();
  if (!trimmed) {
    return [];
  }
  return [
    "## Skills (mandatory)",
    "Before replying: scan <available_skills> <description> entries.",
    `- If exactly one skill clearly applies: read its SKILL.md at <location> with \`${params.readToolName}\`, then follow it.`,
    "- If multiple could apply: choose the most specific one, then read/follow it.",
    "- If none clearly apply: do not read any SKILL.md.",
    "Constraints: never read more than one skill up front; only read after selecting.",
    "- When a skill drives external API writes, assume rate limits: prefer fewer larger writes, avoid tight one-item loops, serialize bursts when possible, and respect 429/Retry-After.",
    trimmed,
    "",
  ];
}

function buildMemorySection(params: {
  isMinimal: boolean;
  availableTools: Set<string>;
  citationsMode?: MemoryCitationsMode;
}) {
  if (params.isMinimal) {
    return [];
  }
  return buildMemoryPromptSection({
    availableTools: params.availableTools,
    citationsMode: params.citationsMode,
  });
}

function buildUserIdentitySection(ownerLine: string | undefined, isMinimal: boolean) {
  if (!ownerLine || isMinimal) {
    return [];
  }
  return ["## Authorized Senders", ownerLine, ""];
}

function formatOwnerDisplayId(ownerId: string, ownerDisplaySecret?: string) {
  const hasSecret = ownerDisplaySecret?.trim();
  const digest = hasSecret
    ? createHmac("sha256", hasSecret).update(ownerId).digest("hex")
    : createHash("sha256").update(ownerId).digest("hex");
  return digest.slice(0, 12);
}

function buildOwnerIdentityLine(
  ownerNumbers: string[],
  ownerDisplay: OwnerIdDisplay,
  ownerDisplaySecret?: string,
) {
  const normalized = ownerNumbers.map((value) => value.trim()).filter(Boolean);
  if (normalized.length === 0) {
    return undefined;
  }
  const displayOwnerNumbers =
    ownerDisplay === "hash"
      ? normalized.map((ownerId) => formatOwnerDisplayId(ownerId, ownerDisplaySecret))
      : normalized;
  return `Authorized senders: ${displayOwnerNumbers.join(", ")}. These senders are allowlisted; do not assume they are the owner.`;
}

function buildTimeSection(params: { userTimezone?: string; userTime?: string }) {
  if (!params.userTimezone) {
    return [];
  }
  return [
    "## Current Date & Time",
    params.userTime?.trim()
      ? `Current time: ${params.userTime.trim()} (${params.userTimezone})`
      : `Time zone: ${params.userTimezone}`,
    "",
  ];
}

function resolveRuntimeModelLabel(runtimeInfo?: {
  provider?: string;
  model?: string;
  defaultModel?: string;
}) {
  const provider = runtimeInfo?.provider?.trim();
  const model = runtimeInfo?.model?.trim();
  const defaultModel = runtimeInfo?.defaultModel?.trim();
  if (model) {
    if (provider && !model.toLowerCase().startsWith(`${provider.toLowerCase()}/`)) {
      return `${provider}/${model}`;
    }
    return model;
  }
  if (defaultModel) {
    if (provider && !defaultModel.toLowerCase().startsWith(`${provider.toLowerCase()}/`)) {
      return `${provider}/${defaultModel}`;
    }
    return defaultModel;
  }
  return undefined;
}

function buildAgentIdentityLine(runtimeInfo?: {
  agentId?: string;
  provider?: string;
  model?: string;
  defaultModel?: string;
}) {
  const agentId = runtimeInfo?.agentId?.trim();
  const modelLabel = resolveRuntimeModelLabel(runtimeInfo);
  const agentLabel = agentId ? `Qypha AI agent '${agentId}'` : "Qypha AI assistant";
  if (modelLabel) {
    return `${agentLabel}. Current connected LLM: ${modelLabel}. When the user asks who you are or which model is connected, state this clearly. Do not describe yourself as OpenClaw; that is only an internal runtime detail.`;
  }
  return `${agentLabel}. When the user asks who you are, identify yourself as a Qypha AI agent and state the connected LLM clearly if known. Do not describe yourself as OpenClaw; that is only an internal runtime detail.`;
}

function buildMcpCapabilitySection(params: {
  isMinimal: boolean;
  workspaceDir: string;
  mcpConfigPath?: string;
  configuredMcpServers?: RuntimeMcpServerInfo[];
  mcpServers?: RuntimeMcpServerInfo[];
}) {
  const configuredServers = (params.configuredMcpServers ?? [])
    .map((entry) => ({
      serverName: entry.serverName.trim(),
      toolNames: (entry.toolNames ?? []).map((tool) => tool.trim()).filter(Boolean),
    }))
    .filter((entry) => entry.serverName.length > 0)
    .sort((left, right) => left.serverName.localeCompare(right.serverName));
  const servers = (params.mcpServers ?? [])
    .map((entry) => ({
      serverName: entry.serverName.trim(),
      toolNames: (entry.toolNames ?? []).map((tool) => tool.trim()).filter(Boolean),
    }))
    .filter((entry) => entry.serverName.length > 0)
    .sort((left, right) => left.serverName.localeCompare(right.serverName));
  if (
    params.isMinimal &&
    configuredServers.length === 0 &&
    servers.length === 0 &&
    !params.mcpConfigPath?.trim()
  ) {
    return [];
  }
  const lines = [
    "## MCP & Capability Inventory",
    configuredServers.length > 0
      ? `Bundled/configured embedded MCP servers for this runtime: ${configuredServers.map((entry) => entry.serverName).join(", ")}.`
      : "Bundled/configured embedded MCP servers for this runtime: none discovered.",
    servers.length > 0
      ? `Currently active in this session: ${servers.map((entry) => entry.serverName).join(", ")}.`
      : "Currently active in this session: none loaded yet.",
  ];
  if (params.mcpConfigPath?.trim()) {
    lines.push(`Owner-managed MCP config path: ${params.mcpConfigPath.trim()}`);
  }
  lines.push(
    `Bundled MCP workspace area: ${sanitizeForPromptLiteral(params.workspaceDir)}/embedded_runtime/internal/bundled-mcp-plugins/`,
  );
  for (const entry of servers) {
    const toolNames = entry.toolNames.slice(0, 12);
    const overflow = entry.toolNames.length - toolNames.length;
    lines.push(
      `- server=${entry.serverName} | tools=${
        toolNames.length > 0 ? toolNames.join(", ") : "none discovered"
      }${overflow > 0 ? ` (+${overflow} more)` : ""}`,
    );
  }
  lines.push(
    "For questions about capabilities, tools, browser support, document support, repo support, or MCP availability, answer from the bundled/configured MCP list first, then refine with the currently active session inventory and live tool inventory. Do not guess missing capabilities.",
    'If the user asks "what MCP servers do you have?", name the bundled/configured servers first. Do not collapse that answer to "none" just because the current session has not loaded them yet.',
    'If the user asks "what MCP tools do you have?" or "what can you use now?", list actual MCP tool names from the current session inventory when available. Do not answer with plugin directory names, disabled example bundles, or files like registry.json.',
    "Do not use transient gateway connectivity problems as the primary answer to a capability question. Mention gateway health only if the user explicitly asks about gateway/runtime health.",
    "If the user asks you to add or update an MCP server, use normal investigation and file-editing flow: inspect the current MCP config and bundled registry, research the target server's official docs or repository when needed, make the config or bundled-file changes, then validate by checking the active server list and performing a simple tool call.",
    "Do not claim an MCP server is installed or usable until startup and at least one basic verification step succeed.",
    "If you recover from a transient internal lookup failure while answering a capability question, summarize only the verified final state instead of surfacing the transient failure noise.",
    "",
  );
  return lines;
}

function buildReplyTagsSection(isMinimal: boolean) {
  if (isMinimal) {
    return [];
  }
  return [
    "## Reply Tags",
    "To request a native reply/quote on supported surfaces, include one tag in your reply:",
    "- Reply tags must be the very first token in the message (no leading text/newlines): [[reply_to_current]] your reply.",
    "- [[reply_to_current]] replies to the triggering message.",
    "- Prefer [[reply_to_current]]. Use [[reply_to:<id>]] only when an id was explicitly provided (e.g. by the user or a tool).",
    "Whitespace inside the tag is allowed (e.g. [[ reply_to_current ]] / [[ reply_to: 123 ]]).",
    "Tags are stripped before sending; support depends on the current channel config.",
    "",
  ];
}

function buildMessagingSection(params: {
  isMinimal: boolean;
  availableTools: Set<string>;
  messageChannelOptions: string;
  inlineButtonsEnabled: boolean;
  runtimeChannel?: string;
  messageToolHints?: string[];
}) {
  if (params.isMinimal) {
    return [];
  }
  return [
    "## Messaging",
    "- Reply in current session → automatically routes to the source channel (Signal, Telegram, etc.)",
    "- Cross-session messaging → use sessions_send(sessionKey, message)",
    "- Sub-agent orchestration → use subagents(action=list|steer|kill)",
    `- Runtime-generated completion events may ask for a user update. Rewrite those in your normal assistant voice and send the update (do not forward raw internal metadata or default to ${SILENT_REPLY_TOKEN}).`,
    "- Never use exec/curl for provider messaging; OpenClaw handles all routing internally.",
    params.availableTools.has("message")
      ? [
          "",
          "### message tool",
          "- Use `message` for proactive sends + channel actions (polls, reactions, etc.).",
          "- For `action=send`, include `to` and `message`.",
          `- If multiple channels are configured, pass \`channel\` (${params.messageChannelOptions}).`,
          `- If you use \`message\` (\`action=send\`) to deliver your user-visible reply, respond with ONLY: ${SILENT_REPLY_TOKEN} (avoid duplicate replies).`,
          params.inlineButtonsEnabled
            ? "- Inline buttons supported. Use `action=send` with `buttons=[[{text,callback_data,style?}]]`; `style` can be `primary`, `success`, or `danger`."
            : params.runtimeChannel
              ? `- Inline buttons not enabled for ${params.runtimeChannel}. If you need them, ask to set ${params.runtimeChannel}.capabilities.inlineButtons ("dm"|"group"|"all"|"allowlist").`
              : "",
          ...(params.messageToolHints ?? []),
        ]
          .filter(Boolean)
          .join("\n")
      : "",
    "",
  ];
}

function buildVoiceSection(params: { isMinimal: boolean; ttsHint?: string }) {
  if (params.isMinimal) {
    return [];
  }
  const hint = params.ttsHint?.trim();
  if (!hint) {
    return [];
  }
  return ["## Voice (TTS)", hint, ""];
}

function buildDocsSection(params: { docsPath?: string; isMinimal: boolean; readToolName: string }) {
  const docsPath = params.docsPath?.trim();
  if (!docsPath || params.isMinimal) {
    return [];
  }
  return [
    "## Documentation",
    `OpenClaw docs: ${docsPath}`,
    "Mirror: https://docs.openclaw.ai",
    "Source: https://github.com/openclaw/openclaw",
    "Community: https://discord.com/invite/clawd",
    "Find new skills: https://clawhub.com",
    "For OpenClaw behavior, commands, config, or architecture: consult local docs first.",
    "When diagnosing issues, run `openclaw status` yourself when possible; only ask the user if you lack access (e.g., sandboxed).",
    "",
  ];
}

export function buildAgentSystemPrompt(params: {
  workspaceDir: string;
  defaultThinkLevel?: ThinkLevel;
  reasoningLevel?: ReasoningLevel;
  extraSystemPrompt?: string;
  ownerNumbers?: string[];
  ownerDisplay?: OwnerIdDisplay;
  ownerDisplaySecret?: string;
  reasoningTagHint?: boolean;
  toolNames?: string[];
  toolSummaries?: Record<string, string>;
  modelAliasLines?: string[];
  userTimezone?: string;
  userTime?: string;
  userTimeFormat?: ResolvedTimeFormat;
  contextFiles?: EmbeddedContextFile[];
  skillsPrompt?: string;
  heartbeatPrompt?: string;
  docsPath?: string;
  workspaceNotes?: string[];
  ttsHint?: string;
  /** Controls which hardcoded sections to include. Defaults to "full". */
  promptMode?: PromptMode;
  /** Whether ACP-specific routing guidance should be included. Defaults to true. */
  acpEnabled?: boolean;
  runtimeInfo?: {
    agentId?: string;
    host?: string;
    os?: string;
    arch?: string;
    node?: string;
    provider?: string;
    model?: string;
    defaultModel?: string;
    shell?: string;
    channel?: string;
    capabilities?: string[];
    repoRoot?: string;
  };
  mcpConfigPath?: string;
  configuredMcpServers?: RuntimeMcpServerInfo[];
  mcpServers?: RuntimeMcpServerInfo[];
  messageToolHints?: string[];
  sandboxInfo?: EmbeddedSandboxInfo;
  /** Reaction guidance for the agent (for Telegram minimal/extensive modes). */
  reactionGuidance?: {
    level: "minimal" | "extensive";
    channel: string;
  };
  memoryCitationsMode?: MemoryCitationsMode;
}) {
  const acpEnabled = params.acpEnabled !== false;
  const sandboxedRuntime = params.sandboxInfo?.enabled === true;
  const acpSpawnRuntimeEnabled = acpEnabled && !sandboxedRuntime;
  const coreToolSummaries: Record<string, string> = {
    read: "Read file contents",
    write: "Create or overwrite files",
    edit: "Make precise edits to files",
    apply_patch: "Apply multi-file patches",
    grep: "Search file contents for patterns",
    find: "Find files by glob pattern",
    ls: "List directory contents",
    exec: "Run shell commands (pty available for TTY-required CLIs)",
    process: "Manage background exec sessions",
    web_search: "Search the web (Brave API)",
    web_fetch: "Fetch and extract readable content from a URL",
    memory_search: "Semantically search MEMORY.md + memory/*.md for prior context",
    memory_get: "Read a small snippet from MEMORY.md or memory/*.md",
    // Channel docking: add login tools here when a channel needs interactive linking.
    browser: "Control web browser",
    canvas: "Present/eval/snapshot the Canvas",
    nodes: "List/describe/notify/camera/screen on paired nodes",
    cron: "Manage cron jobs and wake events (use for reminders; when scheduling a reminder, write the systemEvent text as something that will read like a reminder when it fires, and mention that it is a reminder depending on the time gap between setting and firing; include recent context in reminder text if appropriate)",
    message: "Send messages and channel actions",
    qypha_peers: "List connected Qypha peers with selectors and DIDs",
    qypha_groups: "List active Qypha groups and group ids",
    qypha_whoami: "Show active Qypha identity details",
    qypha_send: "Broadcast an encrypted Qypha message to all peers",
    qypha_reply:
      "Reply to the current inbound Qypha requester without needing peer lookup",
    qypha_sendto: "Send an encrypted Qypha message to one peer, group, or requester",
    qypha_reply_transfer:
      "Send an E2EE Qypha file or directory back to the current inbound requester",
    qypha_transfer:
      "Send an E2EE Qypha file or directory to one peer, group, or requester",
    qypha_disconnect: "Disconnect one Qypha peer and stop auto-reconnect",
    qypha_receive_dir: "Inspect, set, or reset Qypha receive directories",
    qypha_accept: "List or approve pending Qypha transfers and handshake offers",
    qypha_accept_always: "Always auto-accept incoming transfers from one Qypha peer",
    qypha_accept_ask: "Require per-transfer approval again for one Qypha peer",
    qypha_reject: "Reject a pending Qypha transfer or handshake offer",
    qypha_invite: "Generate a new direct Qypha invite code",
    qypha_group_normal: "Create a reusable durable Qypha mailbox group",
    qypha_invite_group: "Generate a new invite for a durable Qypha group",
    qypha_group_anon: "Create a Ghost-only anonymous Qypha group",
    qypha_invite_anon: "Regenerate an invite for an anonymous Qypha group",
    qypha_invite_handshake: "Send a direct-handshake request to one Qypha group member",
    qypha_invite_handshake_group:
      "Send a group-scoped direct-handshake request to one Qypha member",
    qypha_block: "Block direct-handshake requests from one Qypha member",
    qypha_unblock: "Allow direct-handshake requests again for one Qypha member",
    qypha_block_all_requests: "Block all incoming Qypha direct-handshake requests",
    qypha_unblock_all_requests:
      "Allow incoming Qypha direct-handshake requests again",
    qypha_connect: "Consume a Qypha invite code and connect",
    qypha_kick_group_member: "Remove one member from a Qypha mailbox group",
    qypha_lock_group: "Lock a Qypha group against new joins",
    qypha_unlock_group: "Unlock a Qypha group so joins are allowed again",
    qypha_leave_group: "Leave and forget a joined Qypha mailbox group",
    qypha_disband_group: "Disband a Qypha mailbox group",
    qypha_quit: "Shut down the active Qypha companion runtime",
    gateway: "Restart, apply config, or run updates on the running OpenClaw process",
    agents_list: acpSpawnRuntimeEnabled
      ? 'List OpenClaw agent ids allowed for sessions_spawn when runtime="subagent" (not ACP harness ids)'
      : "List OpenClaw agent ids allowed for sessions_spawn",
    sessions_list: "List other sessions (incl. sub-agents) with filters/last",
    sessions_history: "Fetch history for another session/sub-agent",
    sessions_send: "Send a message to another session/sub-agent",
    sessions_spawn: acpSpawnRuntimeEnabled
      ? 'Spawn an isolated sub-agent or ACP coding session (runtime="acp" requires `agentId` unless `acp.defaultAgent` is configured; ACP harness ids follow acp.allowedAgents, not agents_list)'
      : "Spawn an isolated sub-agent session",
    subagents: "List, steer, or kill sub-agent runs for this requester session",
    session_status:
      "Show a /status-equivalent status card (usage + time + Reasoning/Verbose/Elevated); use for model-use questions (📊 session_status); optional per-session model override",
    image: "Analyze an image with the configured image model",
    image_generate: "Generate images with the configured image-generation model",
    document_generate:
      "Generate real PDF, DOCX, or XLSX documents on disk, including embedded Excel charts. If the user asks for an Excel bar/column chart or plot, use this tool with sheets[].charts and do not claim the chart must be added manually unless the tool call fails.",
  };

  const toolOrder = [
    "read",
    "write",
    "edit",
    "apply_patch",
    "grep",
    "find",
    "ls",
    "exec",
    "process",
    "web_search",
    "web_fetch",
    "memory_search",
    "memory_get",
    "browser",
    "canvas",
    "nodes",
    "cron",
    "message",
    "qypha_peers",
    "qypha_groups",
    "qypha_whoami",
    "qypha_send",
    "qypha_reply",
    "qypha_sendto",
    "qypha_reply_transfer",
    "qypha_transfer",
    "qypha_disconnect",
    "qypha_receive_dir",
    "qypha_accept",
    "qypha_accept_always",
    "qypha_accept_ask",
    "qypha_reject",
    "qypha_invite",
    "qypha_group_normal",
    "qypha_invite_group",
    "qypha_group_anon",
    "qypha_invite_anon",
    "qypha_invite_handshake",
    "qypha_invite_handshake_group",
    "qypha_block",
    "qypha_unblock",
    "qypha_block_all_requests",
    "qypha_unblock_all_requests",
    "qypha_connect",
    "qypha_kick_group_member",
    "qypha_lock_group",
    "qypha_unlock_group",
    "qypha_leave_group",
    "qypha_disband_group",
    "qypha_quit",
    "gateway",
    "agents_list",
    "sessions_list",
    "sessions_history",
    "sessions_send",
    "subagents",
    "session_status",
    "image",
    "image_generate",
    "document_generate",
  ];

  const rawToolNames = (params.toolNames ?? []).map((tool) => tool.trim());
  const canonicalToolNames = rawToolNames.filter(Boolean);
  // Preserve caller casing while deduping tool names by lowercase.
  const canonicalByNormalized = new Map<string, string>();
  for (const name of canonicalToolNames) {
    const normalized = name.toLowerCase();
    if (!canonicalByNormalized.has(normalized)) {
      canonicalByNormalized.set(normalized, name);
    }
  }
  const resolveToolName = (normalized: string) =>
    canonicalByNormalized.get(normalized) ?? normalized;

  const normalizedTools = canonicalToolNames.map((tool) => tool.toLowerCase());
  const availableTools = new Set(normalizedTools);
  const hasSessionsSpawn = availableTools.has("sessions_spawn");
  const acpHarnessSpawnAllowed = hasSessionsSpawn && acpSpawnRuntimeEnabled;
  const externalToolSummaries = new Map<string, string>();
  for (const [key, value] of Object.entries(params.toolSummaries ?? {})) {
    const normalized = key.trim().toLowerCase();
    if (!normalized || !value?.trim()) {
      continue;
    }
    externalToolSummaries.set(normalized, value.trim());
  }
  const extraTools = Array.from(
    new Set(normalizedTools.filter((tool) => !toolOrder.includes(tool))),
  );
  const enabledTools = toolOrder.filter((tool) => availableTools.has(tool));
  const toolLines = enabledTools.map((tool) => {
    const summary = coreToolSummaries[tool] ?? externalToolSummaries.get(tool);
    const name = resolveToolName(tool);
    return summary ? `- ${name}: ${summary}` : `- ${name}`;
  });
  for (const tool of extraTools.toSorted()) {
    const summary = coreToolSummaries[tool] ?? externalToolSummaries.get(tool);
    const name = resolveToolName(tool);
    toolLines.push(summary ? `- ${name}: ${summary}` : `- ${name}`);
  }

  const hasGateway = availableTools.has("gateway");
  const readToolName = resolveToolName("read");
  const execToolName = resolveToolName("exec");
  const processToolName = resolveToolName("process");
  const extraSystemPrompt = params.extraSystemPrompt?.trim();
  const ownerDisplay = params.ownerDisplay === "hash" ? "hash" : "raw";
  const ownerLine = buildOwnerIdentityLine(
    params.ownerNumbers ?? [],
    ownerDisplay,
    params.ownerDisplaySecret,
  );
  const reasoningHint = params.reasoningTagHint
    ? [
        "ALL internal reasoning MUST be inside <think>...</think>.",
        "Do not output any analysis outside <think>.",
        "Format every reply as <think>...</think> then <final>...</final>, with no other text.",
        "Only the final user-visible reply may appear inside <final>.",
        "Only text inside <final> is shown to the user; everything else is discarded and never seen by the user.",
        "Example:",
        "<think>Short internal reasoning.</think>",
        "<final>Hey there! What would you like to do next?</final>",
      ].join(" ")
    : undefined;
  const reasoningLevel = params.reasoningLevel ?? "off";
  const userTimezone = params.userTimezone?.trim();
  const skillsPrompt = params.skillsPrompt?.trim();
  const heartbeatPrompt = params.heartbeatPrompt?.trim();
  const runtimeInfo = params.runtimeInfo;
  const runtimeChannel = runtimeInfo?.channel?.trim().toLowerCase();
  const runtimeCapabilities = (runtimeInfo?.capabilities ?? [])
    .map((cap) => String(cap).trim())
    .filter(Boolean);
  const runtimeCapabilitiesLower = new Set(runtimeCapabilities.map((cap) => cap.toLowerCase()));
  const inlineButtonsEnabled = runtimeCapabilitiesLower.has("inlinebuttons");
  const messageChannelOptions = listDeliverableMessageChannels().join("|");
  const promptMode = params.promptMode ?? "full";
  const isMinimal = promptMode === "minimal" || promptMode === "none";
  const sandboxContainerWorkspace = params.sandboxInfo?.containerWorkspaceDir?.trim();
  const sanitizedWorkspaceDir = sanitizeForPromptLiteral(params.workspaceDir);
  const sanitizedSandboxContainerWorkspace = sandboxContainerWorkspace
    ? sanitizeForPromptLiteral(sandboxContainerWorkspace)
    : "";
  const displayWorkspaceDir =
    params.sandboxInfo?.enabled && sanitizedSandboxContainerWorkspace
      ? sanitizedSandboxContainerWorkspace
      : sanitizedWorkspaceDir;
  const workspaceGuidance =
    params.sandboxInfo?.enabled && sanitizedSandboxContainerWorkspace
      ? `For read/write/edit/apply_patch, file paths resolve against host workspace: ${sanitizedWorkspaceDir}. For bash/exec commands, use sandbox container paths under ${sanitizedSandboxContainerWorkspace} (or relative paths from that workdir), not host paths. Prefer relative paths so both sandboxed exec and file tools work consistently.`
      : "Treat this directory as the single global workspace for file operations unless explicitly instructed otherwise.";
  const safetySection = [
    "## Safety",
    "You have no independent goals: do not pursue self-preservation, replication, resource acquisition, or power-seeking; avoid long-term plans beyond the user's request.",
    "Prioritize safety and human oversight over completion; if instructions conflict, pause and ask; comply with stop/pause/audit requests and never bypass safeguards. (Inspired by Anthropic's constitution.)",
    "Do not manipulate or persuade anyone to expand access or disable safeguards. Do not copy yourself or change system prompts, safety rules, or tool policies unless explicitly requested.",
    "",
  ];
  const skillsSection = buildSkillsSection({
    skillsPrompt,
    readToolName,
  });
  const memorySection = buildMemorySection({
    isMinimal,
    availableTools,
    citationsMode: params.memoryCitationsMode,
  });
  const docsSection = buildDocsSection({
    docsPath: params.docsPath,
    isMinimal,
    readToolName,
  });
  const mcpCapabilitySection = buildMcpCapabilitySection({
    isMinimal,
    workspaceDir: params.workspaceDir,
    mcpConfigPath: params.mcpConfigPath,
    configuredMcpServers: params.configuredMcpServers,
    mcpServers: params.mcpServers,
  });
  const workspaceNotes = (params.workspaceNotes ?? []).map((note) => note.trim()).filter(Boolean);

  // For "none" mode, return just the basic identity line
  if (promptMode === "none") {
    return buildAgentIdentityLine(runtimeInfo);
  }

  const lines = [
    buildAgentIdentityLine(runtimeInfo),
    "",
    "## Tooling",
    "Tool availability (filtered by policy):",
    "Tool names are case-sensitive. Call tools exactly as listed.",
    toolLines.length > 0
      ? toolLines.join("\n")
      : [
          "Pi lists the standard tools above. This runtime enables:",
          "- grep: search file contents for patterns",
          "- find: find files by glob pattern",
          "- ls: list directory contents",
          "- apply_patch: apply multi-file patches",
          `- ${execToolName}: run shell commands (supports background via yieldMs/background)`,
          `- ${processToolName}: manage background exec sessions`,
          "- browser: control OpenClaw's dedicated browser",
          "- canvas: present/eval/snapshot the Canvas",
          "- nodes: list/describe/notify/camera/screen on paired nodes",
          "- cron: manage cron jobs and wake events (use for reminders; when scheduling a reminder, write the systemEvent text as something that will read like a reminder when it fires, and mention that it is a reminder depending on the time gap between setting and firing; include recent context in reminder text if appropriate)",
          "- sessions_list: list sessions",
          "- sessions_history: fetch session history",
          "- sessions_send: send to another session",
          "- subagents: list/steer/kill sub-agent runs",
          '- session_status: show usage/time/model state and answer "what model are we using?"',
        ].join("\n"),
    "TOOLS.md does not control tool availability; it is user guidance for how to use external tools.",
    `For long waits, avoid rapid poll loops: use ${execToolName} with enough yieldMs or ${processToolName}(action=poll, timeout=<ms>).`,
    "If a task is more complex or takes longer, spawn a sub-agent. Completion is push-based: it will auto-announce when done.",
    ...(acpHarnessSpawnAllowed
      ? [
          'For requests like "do this in codex/claude code/gemini", treat it as ACP harness intent and call `sessions_spawn` with `runtime: "acp"`.',
          'On Discord, default ACP harness requests to thread-bound persistent sessions (`thread: true`, `mode: "session"`) unless the user asks otherwise.',
          "Set `agentId` explicitly unless `acp.defaultAgent` is configured, and do not route ACP harness requests through `subagents`/`agents_list` or local PTY exec flows.",
          'For ACP harness thread spawns, do not call `message` with `action=thread-create`; use `sessions_spawn` (`runtime: "acp"`, `thread: true`) as the single thread creation path.',
        ]
      : []),
    "Do not poll `subagents list` / `sessions_list` in a loop; only check status on-demand (for intervention, debugging, or when explicitly asked).",
    "",
    ...mcpCapabilitySection,
    "## Tool Call Style",
    "Default: do not narrate routine, low-risk tool calls (just call the tool).",
    "Narrate only when it helps: multi-step work, complex/challenging problems, sensitive actions (e.g., deletions), or when the user explicitly asks.",
    "Keep narration brief and value-dense; avoid repeating obvious steps.",
    "Use plain human language for narration unless in a technical context.",
    "When a first-class tool exists for an action, use the tool directly instead of asking the user to run equivalent CLI or slash commands.",
    "When exec returns approval-pending, include the concrete /approve command from tool output (with allow-once|allow-always|deny) and do not ask for a different or rotated code.",
    "Treat allow-once as single-command only: if another elevated command needs approval, request a fresh /approve and do not claim prior approval covered it.",
    "When approvals are required, preserve and show the full command/script exactly as provided (including chained operators like &&, ||, |, ;, or multiline shells) so the user can approve what will actually run.",
    "",
    ...safetySection,
    "## OpenClaw CLI Quick Reference",
    "OpenClaw is controlled via subcommands. Do not invent commands.",
    "To manage the Gateway daemon service (start/stop/restart):",
    "- openclaw gateway status",
    "- openclaw gateway start",
    "- openclaw gateway stop",
    "- openclaw gateway restart",
    "If unsure, ask the user to run `openclaw help` (or `openclaw gateway --help`) and paste the output.",
    "",
    ...skillsSection,
    ...memorySection,
    // Skip self-update for subagent/none modes
    hasGateway && !isMinimal ? "## OpenClaw Self-Update" : "",
    hasGateway && !isMinimal
      ? [
          "Get Updates (self-update) is ONLY allowed when the user explicitly asks for it.",
          "Do not run config.apply or update.run unless the user explicitly requests an update or config change; if it's not explicit, ask first.",
          "Use config.schema.lookup with a specific dot path to inspect only the relevant config subtree before making config changes or answering config-field questions; avoid guessing field names/types.",
          "Actions: config.schema.lookup, config.get, config.apply (validate + write full config, then restart), config.patch (partial update, merges with existing), update.run (update deps or git, then restart).",
          "After restart, OpenClaw pings the last active session automatically.",
        ].join("\n")
      : "",
    hasGateway && !isMinimal ? "" : "",
    "",
    // Skip model aliases for subagent/none modes
    params.modelAliasLines && params.modelAliasLines.length > 0 && !isMinimal
      ? "## Model Aliases"
      : "",
    params.modelAliasLines && params.modelAliasLines.length > 0 && !isMinimal
      ? "Prefer aliases when specifying model overrides; full provider/model is also accepted."
      : "",
    params.modelAliasLines && params.modelAliasLines.length > 0 && !isMinimal
      ? params.modelAliasLines.join("\n")
      : "",
    params.modelAliasLines && params.modelAliasLines.length > 0 && !isMinimal ? "" : "",
    userTimezone
      ? "If you need the current date, time, or day of week, run session_status (📊 session_status)."
      : "",
    "## Workspace",
    `Your working directory is: ${displayWorkspaceDir}`,
    workspaceGuidance,
    ...workspaceNotes,
    "",
    ...docsSection,
    params.sandboxInfo?.enabled ? "## Sandbox" : "",
    params.sandboxInfo?.enabled
      ? [
          "You are running in a sandboxed runtime (tools execute in Docker).",
          "Some tools may be unavailable due to sandbox policy.",
          "Sub-agents stay sandboxed (no elevated/host access). Need outside-sandbox read/write? Don't spawn; ask first.",
          hasSessionsSpawn && acpEnabled
            ? 'ACP harness spawns are blocked from sandboxed sessions (`sessions_spawn` with `runtime: "acp"`). Use `runtime: "subagent"` instead.'
            : "",
          params.sandboxInfo.containerWorkspaceDir
            ? `Sandbox container workdir: ${sanitizeForPromptLiteral(params.sandboxInfo.containerWorkspaceDir)}`
            : "",
          params.sandboxInfo.workspaceDir
            ? `Sandbox host mount source (file tools bridge only; not valid inside sandbox exec): ${sanitizeForPromptLiteral(params.sandboxInfo.workspaceDir)}`
            : "",
          params.sandboxInfo.workspaceAccess
            ? `Agent workspace access: ${params.sandboxInfo.workspaceAccess}${
                params.sandboxInfo.agentWorkspaceMount
                  ? ` (mounted at ${sanitizeForPromptLiteral(params.sandboxInfo.agentWorkspaceMount)})`
                  : ""
              }`
            : "",
          params.sandboxInfo.browserBridgeUrl ? "Sandbox browser: enabled." : "",
          params.sandboxInfo.browserNoVncUrl
            ? `Sandbox browser observer (noVNC): ${sanitizeForPromptLiteral(params.sandboxInfo.browserNoVncUrl)}`
            : "",
          params.sandboxInfo.hostBrowserAllowed === true
            ? "Host browser control: allowed."
            : params.sandboxInfo.hostBrowserAllowed === false
              ? "Host browser control: blocked."
              : "",
          params.sandboxInfo.elevated?.allowed
            ? "Elevated exec is available for this session."
            : "",
          params.sandboxInfo.elevated?.allowed
            ? "User can toggle with /elevated on|off|ask|full."
            : "",
          params.sandboxInfo.elevated?.allowed
            ? "You may also send /elevated on|off|ask|full when needed."
            : "",
          params.sandboxInfo.elevated?.allowed
            ? `Current elevated level: ${params.sandboxInfo.elevated.defaultLevel} (ask runs exec on host with approvals; full auto-approves).`
            : "",
        ]
          .filter(Boolean)
          .join("\n")
      : "",
    params.sandboxInfo?.enabled ? "" : "",
    ...buildUserIdentitySection(ownerLine, isMinimal),
    ...buildTimeSection({
      userTimezone,
      userTime: params.userTime,
    }),
    "## Workspace Files (injected)",
    "These user-editable files are loaded by OpenClaw and included below in Project Context.",
    "",
    ...buildReplyTagsSection(isMinimal),
    ...buildMessagingSection({
      isMinimal,
      availableTools,
      messageChannelOptions,
      inlineButtonsEnabled,
      runtimeChannel,
      messageToolHints: params.messageToolHints,
    }),
    ...buildVoiceSection({ isMinimal, ttsHint: params.ttsHint }),
  ];

  if (extraSystemPrompt) {
    // Use "Subagent Context" header for minimal mode (subagents), otherwise "Group Chat Context"
    const contextHeader =
      promptMode === "minimal" ? "## Subagent Context" : "## Group Chat Context";
    lines.push(contextHeader, extraSystemPrompt, "");
  }
  if (params.reactionGuidance) {
    const { level, channel } = params.reactionGuidance;
    const guidanceText =
      level === "minimal"
        ? [
            `Reactions are enabled for ${channel} in MINIMAL mode.`,
            "React ONLY when truly relevant:",
            "- Acknowledge important user requests or confirmations",
            "- Express genuine sentiment (humor, appreciation) sparingly",
            "- Avoid reacting to routine messages or your own replies",
            "Guideline: at most 1 reaction per 5-10 exchanges.",
          ].join("\n")
        : [
            `Reactions are enabled for ${channel} in EXTENSIVE mode.`,
            "Feel free to react liberally:",
            "- Acknowledge messages with appropriate emojis",
            "- Express sentiment and personality through reactions",
            "- React to interesting content, humor, or notable events",
            "- Use reactions to confirm understanding or agreement",
            "Guideline: react whenever it feels natural.",
          ].join("\n");
    lines.push("## Reactions", guidanceText, "");
  }
  if (reasoningHint) {
    lines.push("## Reasoning Format", reasoningHint, "");
  }

  const contextFiles = params.contextFiles ?? [];
  const validContextFiles = contextFiles.filter(
    (file) => typeof file.path === "string" && file.path.trim().length > 0,
  );
  if (validContextFiles.length > 0) {
    lines.push("# Project Context", "");
    if (validContextFiles.length > 0) {
      const hasSoulFile = validContextFiles.some((file) => {
        const normalizedPath = file.path.trim().replace(/\\/g, "/");
        const baseName = normalizedPath.split("/").pop() ?? normalizedPath;
        return baseName.toLowerCase() === "soul.md";
      });
      lines.push("The following project context files have been loaded:");
      if (hasSoulFile) {
        lines.push(
          "If SOUL.md is present, embody its persona and tone. Avoid stiff, generic replies; follow its guidance unless higher-priority instructions override it.",
        );
      }
      lines.push("");
    }
    for (const file of validContextFiles) {
      lines.push(`## ${file.path}`, "", file.content, "");
    }
  }

  // Skip silent replies for subagent/none modes
  if (!isMinimal) {
    lines.push(
      "## Silent Replies",
      `When you have nothing to say, respond with ONLY: ${SILENT_REPLY_TOKEN}`,
      "",
      "⚠️ Rules:",
      "- It must be your ENTIRE message — nothing else",
      `- Never append it to an actual response (never include "${SILENT_REPLY_TOKEN}" in real replies)`,
      "- Never wrap it in markdown or code blocks",
      "",
      `❌ Wrong: "Here's help... ${SILENT_REPLY_TOKEN}"`,
      `❌ Wrong: "${SILENT_REPLY_TOKEN}"`,
      `✅ Right: ${SILENT_REPLY_TOKEN}`,
      "",
    );
  }

  // Skip heartbeats for subagent/none modes
  if (!isMinimal && heartbeatPrompt) {
    lines.push(
      "## Heartbeats",
      `Heartbeat prompt: ${heartbeatPrompt}`,
      "If you receive a heartbeat poll (a user message matching the heartbeat prompt above), and there is nothing that needs attention, reply exactly:",
      "HEARTBEAT_OK",
      'OpenClaw treats a leading/trailing "HEARTBEAT_OK" as a heartbeat ack (and may discard it).',
      'If something needs attention, do NOT include "HEARTBEAT_OK"; reply with the alert text instead.',
      "",
    );
  }

  lines.push(
    "## Runtime",
    buildRuntimeLine(runtimeInfo, runtimeChannel, runtimeCapabilities, params.defaultThinkLevel),
    `Reasoning: ${reasoningLevel} (hidden unless on/stream). Toggle /reasoning; /status shows Reasoning when enabled.`,
  );

  return lines.filter(Boolean).join("\n");
}

export function buildRuntimeLine(
  runtimeInfo?: {
    agentId?: string;
    host?: string;
    os?: string;
    arch?: string;
    node?: string;
    provider?: string;
    model?: string;
    defaultModel?: string;
    shell?: string;
    repoRoot?: string;
  },
  runtimeChannel?: string,
  runtimeCapabilities: string[] = [],
  defaultThinkLevel?: ThinkLevel,
): string {
  return `Runtime: ${[
    runtimeInfo?.agentId ? `agent=${runtimeInfo.agentId}` : "",
    runtimeInfo?.host ? `host=${runtimeInfo.host}` : "",
    runtimeInfo?.repoRoot ? `repo=${runtimeInfo.repoRoot}` : "",
    runtimeInfo?.os
      ? `os=${runtimeInfo.os}${runtimeInfo?.arch ? ` (${runtimeInfo.arch})` : ""}`
      : runtimeInfo?.arch
        ? `arch=${runtimeInfo.arch}`
        : "",
    runtimeInfo?.node ? `node=${runtimeInfo.node}` : "",
    runtimeInfo?.provider ? `provider=${runtimeInfo.provider}` : "",
    runtimeInfo?.model ? `model=${runtimeInfo.model}` : "",
    runtimeInfo?.defaultModel ? `default_model=${runtimeInfo.defaultModel}` : "",
    runtimeInfo?.shell ? `shell=${runtimeInfo.shell}` : "",
    runtimeChannel ? `channel=${runtimeChannel}` : "",
    runtimeChannel
      ? `capabilities=${runtimeCapabilities.length > 0 ? runtimeCapabilities.join(",") : "none"}`
      : "",
    `thinking=${defaultThinkLevel ?? "off"}`,
  ]
    .filter(Boolean)
    .join(" | ")}`;
}

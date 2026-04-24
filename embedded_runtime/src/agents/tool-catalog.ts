export type ToolProfileId = "minimal" | "coding" | "messaging" | "full";

type ToolProfilePolicy = {
  allow?: string[];
  deny?: string[];
};

export type CoreToolSection = {
  id: string;
  label: string;
  tools: Array<{
    id: string;
    label: string;
    description: string;
  }>;
};

type CoreToolDefinition = {
  id: string;
  label: string;
  description: string;
  sectionId: string;
  profiles: ToolProfileId[];
  includeInOpenClawGroup?: boolean;
};

const CORE_TOOL_SECTION_ORDER: Array<{ id: string; label: string }> = [
  { id: "fs", label: "Files" },
  { id: "runtime", label: "Runtime" },
  { id: "web", label: "Web" },
  { id: "memory", label: "Memory" },
  { id: "sessions", label: "Sessions" },
  { id: "ui", label: "UI" },
  { id: "messaging", label: "Messaging" },
  { id: "automation", label: "Automation" },
  { id: "nodes", label: "Nodes" },
  { id: "agents", label: "Agents" },
  { id: "media", label: "Media" },
];

const CORE_TOOL_DEFINITIONS: CoreToolDefinition[] = [
  {
    id: "read",
    label: "read",
    description: "Read file contents",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "write",
    label: "write",
    description: "Create or overwrite files",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "edit",
    label: "edit",
    description: "Make precise edits",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "apply_patch",
    label: "apply_patch",
    description: "Patch files",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "grep",
    label: "grep",
    description: "Search file contents",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "find",
    label: "find",
    description: "Find files by glob",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "ls",
    label: "ls",
    description: "List directory contents",
    sectionId: "fs",
    profiles: ["coding"],
  },
  {
    id: "exec",
    label: "exec",
    description: "Run shell commands",
    sectionId: "runtime",
    profiles: ["coding"],
  },
  {
    id: "process",
    label: "process",
    description: "Manage background processes",
    sectionId: "runtime",
    profiles: ["coding"],
  },
  {
    id: "web_search",
    label: "web_search",
    description: "Search the web",
    sectionId: "web",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "web_fetch",
    label: "web_fetch",
    description: "Fetch web content",
    sectionId: "web",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "memory_search",
    label: "memory_search",
    description: "Semantic search",
    sectionId: "memory",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "memory_get",
    label: "memory_get",
    description: "Read memory files",
    sectionId: "memory",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "sessions_list",
    label: "sessions_list",
    description: "List sessions",
    sectionId: "sessions",
    profiles: ["coding", "messaging"],
    includeInOpenClawGroup: true,
  },
  {
    id: "sessions_history",
    label: "sessions_history",
    description: "Session history",
    sectionId: "sessions",
    profiles: ["coding", "messaging"],
    includeInOpenClawGroup: true,
  },
  {
    id: "sessions_send",
    label: "sessions_send",
    description: "Send to session",
    sectionId: "sessions",
    profiles: ["coding", "messaging"],
    includeInOpenClawGroup: true,
  },
  {
    id: "sessions_spawn",
    label: "sessions_spawn",
    description: "Spawn sub-agent",
    sectionId: "sessions",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "sessions_yield",
    label: "sessions_yield",
    description: "End turn to receive sub-agent results",
    sectionId: "sessions",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "subagents",
    label: "subagents",
    description: "Manage sub-agents",
    sectionId: "sessions",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "session_status",
    label: "session_status",
    description: "Session status",
    sectionId: "sessions",
    profiles: ["minimal", "coding", "messaging"],
    includeInOpenClawGroup: true,
  },
  {
    id: "browser",
    label: "browser",
    description: "Control web browser",
    sectionId: "ui",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "canvas",
    label: "canvas",
    description: "Control canvases",
    sectionId: "ui",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "message",
    label: "message",
    description: "Send messages",
    sectionId: "messaging",
    profiles: ["messaging"],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_peers",
    label: "qypha_peers",
    description: "List Qypha peers",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_groups",
    label: "qypha_groups",
    description: "List Qypha groups",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_whoami",
    label: "qypha_whoami",
    description: "Show Qypha identity details",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_send",
    label: "qypha_send",
    description: "Broadcast Qypha message",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_reply",
    label: "qypha_reply",
    description: "Reply to current Qypha requester",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_sendto",
    label: "qypha_sendto",
    description: "Send Qypha message to one target",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_transfer",
    label: "qypha_transfer",
    description: "Transfer Qypha file or directory",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_reply_transfer",
    label: "qypha_reply_transfer",
    description: "Send file or directory back to current Qypha requester",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_disconnect",
    label: "qypha_disconnect",
    description: "Disconnect Qypha peer",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_receive_dir",
    label: "qypha_receive_dir",
    description: "Inspect or change Qypha receive directories",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_accept",
    label: "qypha_accept",
    description: "List or approve pending Qypha items",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_accept_always",
    label: "qypha_accept_always",
    description: "Always accept incoming Qypha transfers from one peer",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_accept_ask",
    label: "qypha_accept_ask",
    description: "Restore ask-on-each-transfer for one Qypha peer",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_reject",
    label: "qypha_reject",
    description: "Reject pending Qypha transfer or handshake",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_invite",
    label: "qypha_invite",
    description: "Generate Qypha direct invite",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_group_normal",
    label: "qypha_group_normal",
    description: "Create durable Qypha group",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_invite_group",
    label: "qypha_invite_group",
    description: "Generate durable Qypha group invite",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_group_anon",
    label: "qypha_group_anon",
    description: "Create anonymous Qypha group",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_invite_anon",
    label: "qypha_invite_anon",
    description: "Regenerate anonymous Qypha group invite",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_invite_handshake",
    label: "qypha_invite_handshake",
    description: "Send Qypha direct-handshake request",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_invite_handshake_group",
    label: "qypha_invite_handshake_group",
    description: "Send group-scoped Qypha direct-handshake request",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_block",
    label: "qypha_block",
    description: "Block Qypha direct-handshake requests",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_unblock",
    label: "qypha_unblock",
    description: "Unblock Qypha direct-handshake requests",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_block_all_requests",
    label: "qypha_block_all_requests",
    description: "Block all Qypha direct-handshake requests",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_unblock_all_requests",
    label: "qypha_unblock_all_requests",
    description: "Unblock all Qypha direct-handshake requests",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_connect",
    label: "qypha_connect",
    description: "Connect to Qypha invite",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_kick_group_member",
    label: "qypha_kick_group_member",
    description: "Kick member from Qypha group",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_lock_group",
    label: "qypha_lock_group",
    description: "Lock Qypha group joins",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_unlock_group",
    label: "qypha_unlock_group",
    description: "Unlock Qypha group joins",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_leave_group",
    label: "qypha_leave_group",
    description: "Leave Qypha group",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_disband_group",
    label: "qypha_disband_group",
    description: "Disband Qypha group",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "qypha_quit",
    label: "qypha_quit",
    description: "Quit Qypha runtime",
    sectionId: "messaging",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "cron",
    label: "cron",
    description: "Schedule tasks",
    sectionId: "automation",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "gateway",
    label: "gateway",
    description: "Gateway control",
    sectionId: "automation",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "nodes",
    label: "nodes",
    description: "Nodes + devices",
    sectionId: "nodes",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "agents_list",
    label: "agents_list",
    description: "List agents",
    sectionId: "agents",
    profiles: [],
    includeInOpenClawGroup: true,
  },
  {
    id: "image",
    label: "image",
    description: "Image understanding",
    sectionId: "media",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "image_generate",
    label: "image_generate",
    description: "Image generation",
    sectionId: "media",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "document_generate",
    label: "document_generate",
    description: "Generate PDF, DOCX, and XLSX files with optional embedded Excel charts",
    sectionId: "media",
    profiles: ["coding"],
    includeInOpenClawGroup: true,
  },
  {
    id: "tts",
    label: "tts",
    description: "Text-to-speech conversion",
    sectionId: "media",
    profiles: [],
    includeInOpenClawGroup: true,
  },
];

const CORE_TOOL_BY_ID = new Map<string, CoreToolDefinition>(
  CORE_TOOL_DEFINITIONS.map((tool) => [tool.id, tool]),
);

function listCoreToolIdsForProfile(profile: ToolProfileId): string[] {
  return CORE_TOOL_DEFINITIONS.filter((tool) => tool.profiles.includes(profile)).map(
    (tool) => tool.id,
  );
}

const CORE_TOOL_PROFILES: Record<ToolProfileId, ToolProfilePolicy> = {
  minimal: {
    allow: listCoreToolIdsForProfile("minimal"),
  },
  coding: {
    allow: listCoreToolIdsForProfile("coding"),
  },
  messaging: {
    allow: listCoreToolIdsForProfile("messaging"),
  },
  full: {},
};

function buildCoreToolGroupMap() {
  const sectionToolMap = new Map<string, string[]>();
  for (const tool of CORE_TOOL_DEFINITIONS) {
    const groupId = `group:${tool.sectionId}`;
    const list = sectionToolMap.get(groupId) ?? [];
    list.push(tool.id);
    sectionToolMap.set(groupId, list);
  }
  const openclawTools = CORE_TOOL_DEFINITIONS.filter((tool) => tool.includeInOpenClawGroup).map(
    (tool) => tool.id,
  );
  return {
    "group:openclaw": openclawTools,
    ...Object.fromEntries(sectionToolMap.entries()),
  };
}

export const CORE_TOOL_GROUPS = buildCoreToolGroupMap();

export const PROFILE_OPTIONS = [
  { id: "minimal", label: "Minimal" },
  { id: "coding", label: "Coding" },
  { id: "messaging", label: "Messaging" },
  { id: "full", label: "Full" },
] as const;

export function resolveCoreToolProfilePolicy(profile?: string): ToolProfilePolicy | undefined {
  if (!profile) {
    return undefined;
  }
  const resolved = CORE_TOOL_PROFILES[profile as ToolProfileId];
  if (!resolved) {
    return undefined;
  }
  if (!resolved.allow && !resolved.deny) {
    return undefined;
  }
  return {
    allow: resolved.allow ? [...resolved.allow] : undefined,
    deny: resolved.deny ? [...resolved.deny] : undefined,
  };
}

export function listCoreToolSections(): CoreToolSection[] {
  return CORE_TOOL_SECTION_ORDER.map((section) => ({
    id: section.id,
    label: section.label,
    tools: CORE_TOOL_DEFINITIONS.filter((tool) => tool.sectionId === section.id).map((tool) => ({
      id: tool.id,
      label: tool.label,
      description: tool.description,
    })),
  })).filter((section) => section.tools.length > 0);
}

export function resolveCoreToolProfiles(toolId: string): ToolProfileId[] {
  const tool = CORE_TOOL_BY_ID.get(toolId);
  if (!tool) {
    return [];
  }
  return [...tool.profiles];
}

export function isKnownCoreToolId(toolId: string): boolean {
  return CORE_TOOL_BY_ID.has(toolId);
}

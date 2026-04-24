import { readConfigFileSnapshot, writeConfigFile } from "./io.js";
import type { OpenClawConfig } from "./types.openclaw.js";
import { validateConfigObjectWithPlugins } from "./validation.js";
import { verifyStdioMcpServer } from "../agents/mcp-stdio.js";

export type ConfigMcpServers = Record<string, Record<string, unknown>>;

type ConfigMcpReadResult =
  | { ok: true; path: string; config: OpenClawConfig; mcpServers: ConfigMcpServers }
  | { ok: false; path: string; error: string };

type ConfigMcpWriteResult =
  | {
      ok: true;
      path: string;
      config: OpenClawConfig;
      mcpServers: ConfigMcpServers;
      removed?: boolean;
      verification?: {
        launchSummary: string;
        toolNames: string[];
      };
    }
  | { ok: false; path: string; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function normalizeConfiguredMcpServers(value: unknown): ConfigMcpServers {
  if (!isRecord(value)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, server]) => isRecord(server))
      .map(([name, server]) => [name, { ...(server as Record<string, unknown>) }]),
  );
}

export async function listConfiguredMcpServers(): Promise<ConfigMcpReadResult> {
  const snapshot = await readConfigFileSnapshot();
  if (!snapshot.valid) {
    return {
      ok: false,
      path: snapshot.path,
      error: "Config file is invalid; fix it before using MCP config commands.",
    };
  }
  return {
    ok: true,
    path: snapshot.path,
    config: structuredClone(snapshot.resolved),
    mcpServers: normalizeConfiguredMcpServers(snapshot.resolved.mcp?.servers),
  };
}

export async function setConfiguredMcpServer(params: {
  name: string;
  server: unknown;
}): Promise<ConfigMcpWriteResult> {
  const name = params.name.trim();
  if (!name) {
    return { ok: false, path: "", error: "MCP server name is required." };
  }
  if (!isRecord(params.server)) {
    return { ok: false, path: "", error: "MCP server config must be a JSON object." };
  }

  const loaded = await listConfiguredMcpServers();
  if (!loaded.ok) {
    return loaded;
  }

  const next = structuredClone(loaded.config);
  const servers = normalizeConfiguredMcpServers(next.mcp?.servers);
  servers[name] = { ...params.server };
  next.mcp = {
    ...next.mcp,
    servers,
  };

  const validated = validateConfigObjectWithPlugins(next);
  if (!validated.ok) {
    const issue = validated.issues[0];
    return {
      ok: false,
      path: loaded.path,
      error: `Config invalid after MCP set (${issue.path}: ${issue.message}).`,
    };
  }
  const verified = await verifyStdioMcpServer({
    raw: servers[name],
    clientName: "openclaw-mcp-config",
    timeoutMs: 20_000,
  });
  if (!verified.ok) {
    const launchSuffix = verified.launchSummary ? ` (${verified.launchSummary})` : "";
    const stderrSuffix =
      verified.stderrTail && verified.stderrTail.length > 0
        ? ` stderr: ${verified.stderrTail.join(" | ")}`
        : "";
    return {
      ok: false,
      path: loaded.path,
      error:
        `MCP server "${name}" failed verification${launchSuffix}: ${verified.reason}.` +
        stderrSuffix,
    };
  }
  await writeConfigFile(validated.config);
  return {
    ok: true,
    path: loaded.path,
    config: validated.config,
    mcpServers: servers,
    verification: {
      launchSummary: verified.launchSummary,
      toolNames: verified.toolNames,
    },
  };
}

export async function unsetConfiguredMcpServer(params: {
  name: string;
}): Promise<ConfigMcpWriteResult> {
  const name = params.name.trim();
  if (!name) {
    return { ok: false, path: "", error: "MCP server name is required." };
  }

  const loaded = await listConfiguredMcpServers();
  if (!loaded.ok) {
    return loaded;
  }
  if (!Object.hasOwn(loaded.mcpServers, name)) {
    return {
      ok: true,
      path: loaded.path,
      config: loaded.config,
      mcpServers: loaded.mcpServers,
      removed: false,
    };
  }

  const next = structuredClone(loaded.config);
  const servers = normalizeConfiguredMcpServers(next.mcp?.servers);
  delete servers[name];
  if (Object.keys(servers).length > 0) {
    next.mcp = {
      ...next.mcp,
      servers,
    };
  } else if (next.mcp) {
    delete next.mcp.servers;
    if (Object.keys(next.mcp).length === 0) {
      delete next.mcp;
    }
  }

  const validated = validateConfigObjectWithPlugins(next);
  if (!validated.ok) {
    const issue = validated.issues[0];
    return {
      ok: false,
      path: loaded.path,
      error: `Config invalid after MCP unset (${issue.path}: ${issue.message}).`,
    };
  }
  await writeConfigFile(validated.config);
  return {
    ok: true,
    path: loaded.path,
    config: validated.config,
    mcpServers: servers,
    removed: true,
  };
}

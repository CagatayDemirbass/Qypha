import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

type StdioMcpServerLaunchConfig = {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
};

type StdioMcpServerLaunchResult =
  | { ok: true; config: StdioMcpServerLaunchConfig }
  | { ok: false; reason: string };

type VerifyStdioMcpServerResult =
  | {
      ok: true;
      config: StdioMcpServerLaunchConfig;
      launchSummary: string;
      toolNames: string[];
    }
  | {
      ok: false;
      reason: string;
      launchSummary?: string;
      stderrTail?: string[];
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function toStringRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const entries = Object.entries(value)
    .map(([key, entry]) => {
      if (typeof entry === "string") {
        return [key, entry] as const;
      }
      if (typeof entry === "number" || typeof entry === "boolean") {
        return [key, String(entry)] as const;
      }
      return null;
    })
    .filter((entry): entry is readonly [string, string] => entry !== null);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function toStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const entries = value.filter((entry): entry is string => typeof entry === "string");
  return entries.length > 0 ? entries : [];
}

function createTimeoutError(message: string): Error {
  const error = new Error(message);
  error.name = "TimeoutError";
  return error;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(createTimeoutError(message)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

export async function listAllMcpTools(client: Client): Promise<string[]> {
  const toolNames: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    for (const tool of page.tools) {
      const name = tool.name.trim();
      if (name) {
        toolNames.push(name);
      }
    }
    cursor = page.nextCursor;
  } while (cursor);
  return Array.from(new Set(toolNames)).sort((left, right) => left.localeCompare(right));
}

export function resolveStdioMcpServerLaunchConfig(raw: unknown): StdioMcpServerLaunchResult {
  if (!isRecord(raw)) {
    return { ok: false, reason: "server config must be an object" };
  }
  if (typeof raw.command !== "string" || raw.command.trim().length === 0) {
    if (typeof raw.url === "string" && raw.url.trim().length > 0) {
      return {
        ok: false,
        reason: "only stdio MCP servers are supported right now",
      };
    }
    return { ok: false, reason: "its command is missing" };
  }
  const cwd =
    typeof raw.cwd === "string" && raw.cwd.trim().length > 0
      ? raw.cwd
      : typeof raw.workingDirectory === "string" && raw.workingDirectory.trim().length > 0
        ? raw.workingDirectory
        : undefined;
  return {
    ok: true,
    config: {
      command: raw.command,
      args: toStringArray(raw.args),
      env: toStringRecord(raw.env),
      cwd,
    },
  };
}

export function describeStdioMcpServerLaunchConfig(config: StdioMcpServerLaunchConfig): string {
  const args =
    Array.isArray(config.args) && config.args.length > 0 ? ` ${config.args.join(" ")}` : "";
  const cwd = config.cwd ? ` (cwd=${config.cwd})` : "";
  return `${config.command}${args}${cwd}`;
}

export async function verifyStdioMcpServer(params: {
  raw: unknown;
  clientName?: string;
  clientVersion?: string;
  timeoutMs?: number;
}): Promise<VerifyStdioMcpServerResult> {
  const launch = resolveStdioMcpServerLaunchConfig(params.raw);
  if (!launch.ok) {
    return { ok: false, reason: launch.reason };
  }
  const launchSummary = describeStdioMcpServerLaunchConfig(launch.config);
  const timeoutMs = Math.max(1_000, params.timeoutMs ?? 15_000);
  const stderrTail: string[] = [];
  const transport = new StdioClientTransport({
    command: launch.config.command,
    args: launch.config.args,
    env: launch.config.env,
    cwd: launch.config.cwd,
    stderr: "pipe",
  });
  const stderr = transport.stderr;
  const onData = (chunk: Buffer | string) => {
    const message = String(chunk).trim();
    if (!message) {
      return;
    }
    for (const line of message.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      stderrTail.push(trimmed);
      if (stderrTail.length > 20) {
        stderrTail.splice(0, stderrTail.length - 20);
      }
    }
  };
  if (stderr && typeof stderr.on === "function") {
    stderr.on("data", onData);
  }
  const client = new Client(
    {
      name: params.clientName?.trim() || "openclaw-mcp-verify",
      version: params.clientVersion?.trim() || "0.0.0",
    },
    {},
  );
  try {
    await withTimeout(
      client.connect(transport),
      timeoutMs,
      `timed out starting MCP server after ${timeoutMs}ms`,
    );
    const toolNames = await withTimeout(
      listAllMcpTools(client),
      timeoutMs,
      `timed out listing MCP tools after ${timeoutMs}ms`,
    );
    if (toolNames.length === 0) {
      return {
        ok: false,
        reason: "server started but did not expose any MCP tools",
        launchSummary,
        stderrTail,
      };
    }
    return {
      ok: true,
      config: launch.config,
      launchSummary,
      toolNames,
    };
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof Error ? error.message : String(error),
      launchSummary,
      stderrTail,
    };
  } finally {
    if (stderr) {
      if (typeof stderr.off === "function") {
        stderr.off("data", onData);
      } else if (typeof stderr.removeListener === "function") {
        stderr.removeListener("data", onData);
      }
    }
    await client.close().catch(() => {});
    await transport.close().catch(() => {});
  }
}

export type { StdioMcpServerLaunchConfig, StdioMcpServerLaunchResult, VerifyStdioMcpServerResult };

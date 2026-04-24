import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { OpenClawConfig } from "../config/config.js";
import { applyMergePatch } from "../config/merge-patch.js";

function normalizeOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function resolveRuntimeRootDir(runtimeRootDir?: string): string {
  if (runtimeRootDir?.trim()) {
    return path.resolve(runtimeRootDir);
  }
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
}

function resolveBundledCapabilityPluginRoot(runtimeRootDir?: string): string {
  return path.resolve(resolveRuntimeRootDir(runtimeRootDir), "internal/bundled-mcp-plugins");
}

function resolveBundledPlaywrightOutputDir(runtimeRootDir?: string): string {
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
      : path.resolve(resolveBundledCapabilityPluginRoot(runtimeRootDir), ".runtime-state");
  return path.resolve(stateRoot, "playwright-mcp-output");
}

type BundledCapabilityRegistryEntry = {
  dir?: string;
  enabled?: unknown;
};

function resolveBundledCapabilityRegistryEntries(
  runtimeRootDir?: string,
): BundledCapabilityRegistryEntry[] {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot(runtimeRootDir);
  const registryPath = path.resolve(bundledPluginsDir, "registry.json");
  try {
    const parsed = JSON.parse(fs.readFileSync(registryPath, "utf-8")) as { plugins?: unknown };
    return Array.isArray(parsed.plugins) ? parsed.plugins : [];
  } catch {
    return [];
  }
}

function resolveBundledCapabilityPluginLoadPaths(runtimeRootDir?: string): string[] {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot(runtimeRootDir);
  const registryEntries = resolveBundledCapabilityRegistryEntries(runtimeRootDir);
  return registryEntries
    .filter(
      (entry): entry is { dir: string; enabled?: unknown } =>
        !!entry && typeof entry.dir === "string" && entry.dir.trim().length > 0,
    )
    .filter((entry) => entry.enabled !== false)
    .map((entry) => path.resolve(bundledPluginsDir, entry.dir))
    .filter((entry) => fs.existsSync(entry));
}

function buildBundledCapabilityMcpServers(params: {
  workspaceDir?: string;
  runtimeRootDir?: string;
}): Record<string, Record<string, unknown>> {
  const bundledPluginsDir = resolveBundledCapabilityPluginRoot(params.runtimeRootDir);
  const resolvedWorkspaceDir = path.resolve(params.workspaceDir ?? process.cwd());
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
      args: [filesystemServerPath, resolvedWorkspaceDir],
      cwd: resolvedWorkspaceDir,
    },
    git: {
      command: process.execPath,
      args: [gitLauncherPath],
    },
    fetch: {
      command: process.execPath,
      args: [fetchLauncherPath],
    },
  };

  const playwrightArgs = [
    playwrightCliPath,
    "--browser",
    "chromium",
    "--isolated",
    "--headless",
    "--output-dir",
    resolveBundledPlaywrightOutputDir(params.runtimeRootDir),
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

export function buildEmbeddedCapabilityConfig(params: {
  workspaceDir?: string;
  baseConfig?: OpenClawConfig;
  runtimeRootDir?: string;
}): OpenClawConfig {
  const bundledPluginLoadPaths = resolveBundledCapabilityPluginLoadPaths(params.runtimeRootDir);
  const bundledMcpServers = buildBundledCapabilityMcpServers({
    workspaceDir: params.workspaceDir,
    runtimeRootDir: params.runtimeRootDir,
  });
  const defaults: OpenClawConfig = {
    plugins: {
      enabled: true,
      ...(bundledPluginLoadPaths.length > 0
        ? {
            load: {
              paths: bundledPluginLoadPaths,
            },
          }
        : {}),
      slots: {
        memory: "memory-core",
      },
    },
    agents: {
      defaults: {
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
    ...(Object.keys(bundledMcpServers).length > 0
      ? {
          mcp: {
            servers: bundledMcpServers,
          },
        }
      : {}),
  };
  return applyMergePatch(defaults, params.baseConfig ?? {}) as OpenClawConfig;
}

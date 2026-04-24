import type { OpenClawConfig } from "../config/config.js";
import type { BundleMcpDiagnostic, BundleMcpServerConfig } from "../plugins/bundle-mcp.js";
import { loadEnabledBundleMcpConfig } from "../plugins/bundle-mcp.js";

export type EmbeddedPiMcpConfig = {
  mcpServers: Record<string, BundleMcpServerConfig>;
  diagnostics: BundleMcpDiagnostic[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeConfiguredMcpServers(value: unknown): Record<string, BundleMcpServerConfig> {
  if (!isRecord(value)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, server]) => isRecord(server))
      .map(([name, server]) => [name, { ...(server as Record<string, unknown>) }]),
  );
}

export function loadEmbeddedPiMcpConfig(params: {
  workspaceDir: string;
  cfg?: OpenClawConfig;
}): EmbeddedPiMcpConfig {
  const bundleMcp = loadEnabledBundleMcpConfig({
    workspaceDir: params.workspaceDir,
    cfg: params.cfg,
  });
  const configuredMcp = normalizeConfiguredMcpServers(params.cfg?.mcp?.servers);

  return {
    // OpenClaw config is the owner-managed layer, so it overrides bundle defaults.
    mcpServers: {
      ...bundleMcp.config.mcpServers,
      ...configuredMcp,
    },
    diagnostics: bundleMcp.diagnostics,
  };
}

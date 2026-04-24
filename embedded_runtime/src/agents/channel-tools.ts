import type { OpenClawConfig } from "../config/config.js";
import type { ChannelAgentTool, ChannelMessageActionName } from "../channels/plugins/types.js";

// Qypha embedded worker does not expose external OpenClaw channel plugins.
// Keep the tool surface focused on provider/research/browser/document/os flows.

export function listChannelSupportedActions(_params: {
  cfg?: OpenClawConfig;
  channel?: string;
  currentChannelId?: string | null;
  currentThreadTs?: string | null;
  currentMessageId?: string | number | null;
  accountId?: string | null;
  sessionKey?: string | null;
  sessionId?: string | null;
  agentId?: string | null;
  requesterSenderId?: string | null;
}): ChannelMessageActionName[] {
  return [];
}

export function listAllChannelSupportedActions(_params: {
  cfg?: OpenClawConfig;
  currentChannelId?: string | null;
  currentThreadTs?: string | null;
  currentMessageId?: string | number | null;
  accountId?: string | null;
  sessionKey?: string | null;
  sessionId?: string | null;
  agentId?: string | null;
  requesterSenderId?: string | null;
}): ChannelMessageActionName[] {
  return [];
}

export function listChannelAgentTools(_params: { cfg?: OpenClawConfig }): ChannelAgentTool[] {
  return [];
}

export function resolveChannelMessageToolHints(_params: {
  cfg?: OpenClawConfig;
  channel?: string | null;
  accountId?: string | null;
}): string[] {
  return [];
}

export const __testing = {
  resetLoggedListActionErrors() {},
};

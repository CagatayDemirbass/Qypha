import type { ChannelId, ChannelPlugin } from "./types.js";

// Qypha embedded worker does not load OpenClaw bundled channel plugins.

export const bundledChannelPlugins = [] as ChannelPlugin[];

export const bundledChannelSetupPlugins = [] as ChannelPlugin[];

export function getBundledChannelPlugin(_id: ChannelId): ChannelPlugin | undefined {
  return undefined;
}

export function requireBundledChannelPlugin(id: ChannelId): ChannelPlugin {
  throw new Error(`bundled channel plugin unavailable in embedded worker: ${id}`);
}

export const bundledChannelRuntimeSetters = {
  setDiscordRuntime() {},
  setLineRuntime() {},
  setTelegramRuntime() {},
};

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { buildPromptSection } from "./src/prompt-section.js";
import { createMemoryGetTool, createMemorySearchTool } from "./src/tools.js";

export { buildPromptSection } from "./src/prompt-section.js";

export default definePluginEntry({
  id: "memory-core",
  name: "Memory (Core)",
  description: "File-backed memory search tools and CLI",
  kind: "memory",
  register(api) {
    api.registerMemoryPromptSection(buildPromptSection);

    api.registerTool(
      (ctx) =>
        createMemorySearchTool({
          config: ctx.config,
          agentSessionKey: ctx.sessionKey,
        }),
      { names: ["memory_search"] },
    );

    api.registerTool(
      (ctx) =>
        createMemoryGetTool({
          config: ctx.config,
          agentSessionKey: ctx.sessionKey,
        }),
      { names: ["memory_get"] },
    );

    api.registerCli(
      ({ program }) => {
        api.runtime.tools.registerMemoryCli(program);
      },
      { commands: ["memory"] },
    );
  },
});

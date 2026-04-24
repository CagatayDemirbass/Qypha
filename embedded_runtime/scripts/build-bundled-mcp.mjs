import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const runtimeRoot = path.resolve(scriptDir, "..");

async function buildFilesystemServer() {
  const pluginRoot = path.join(
    runtimeRoot,
    "internal",
    "bundled-mcp-plugins",
    "filesystem-server",
  );
  await build({
    entryPoints: [path.join(pluginRoot, "upstream", "index.ts")],
    outfile: path.join(pluginRoot, "servers", "filesystem-server.mjs"),
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node22",
    absWorkingDir: runtimeRoot,
  });
}

await buildFilesystemServer();

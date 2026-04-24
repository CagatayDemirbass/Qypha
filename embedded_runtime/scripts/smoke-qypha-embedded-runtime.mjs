#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const runtimeRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(runtimeRoot, "..");
const workerPath = path.join(runtimeRoot, "dist", "worker-entry.js");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeError(error) {
  return error instanceof Error ? error.message : String(error);
}

async function startFixtureServer(html) {
  const server = http.createServer((request, response) => {
    if (request.url === "/browser.html") {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(html);
      return;
    }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("fixture server did not expose a TCP address");
  }

  return {
    url: `http://127.0.0.1:${address.port}/browser.html`,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    },
  };
}

async function makeTempRuntime() {
  const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "qypha-embedded-smoke-"));
  const runtimeHome = path.join(tempRoot, "home");
  const runtimeState = path.join(tempRoot, "state");
  const runtimeConfig = path.join(tempRoot, "qypha-runtime.json");
  const fixtureDir = path.join(tempRoot, "fixtures");
  await fsp.mkdir(runtimeHome, { recursive: true });
  await fsp.mkdir(runtimeState, { recursive: true });
  await fsp.mkdir(fixtureDir, { recursive: true });
  await fsp.writeFile(
    runtimeConfig,
    `${JSON.stringify(
      {
        browser: {
          ssrfPolicy: {
            dangerouslyAllowPrivateNetwork: true,
            allowedHostnames: ["127.0.0.1", "localhost"],
          },
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  return {
    tempRoot,
    runtimeHome,
    runtimeState,
    runtimeConfig,
    fixtureDir,
    debugLogPath: path.join(tempRoot, "worker.log"),
  };
}

class WorkerSession {
  constructor(params) {
    this.workerPath = params.workerPath;
    this.runtimeRoot = params.runtimeRoot;
    this.env = params.env;
    this.child = null;
    this.stderr = "";
    this.readline = null;
    this.pending = [];
  }

  async start() {
    this.child = spawn(process.execPath, [this.workerPath], {
      cwd: this.runtimeRoot,
      env: this.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stderr.on("data", (chunk) => {
      this.stderr += chunk.toString();
    });
    this.readline = readline.createInterface({
      input: this.child.stdout,
      crlfDelay: Infinity,
    });
    this.readline.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return;
      }
      try {
        const parsed = JSON.parse(trimmed);
        const entry = this.pending.shift();
        if (!entry) {
          return;
        }
        clearTimeout(entry.timer);
        entry.resolve(parsed);
      } catch {
        this.stderr += `[worker-stdout] ${trimmed}\n`;
      }
    });
    this.child.on("exit", (code, signal) => {
      while (this.pending.length > 0) {
        const entry = this.pending.shift();
        if (!entry) {
          continue;
        }
        clearTimeout(entry.timer);
        entry.reject(
          new Error(`worker exited before responding (code=${code ?? "null"} signal=${signal ?? "null"})`),
        );
      }
    });
  }

  async request(op, payload = undefined, timeoutMs = 30_000) {
    if (!this.child || !this.readline) {
      throw new Error("worker session is not started");
    }
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.pending.findIndex((entry) => entry.timer === timer);
        if (index >= 0) {
          this.pending.splice(index, 1);
        }
        reject(new Error(`timeout waiting for ${op}`));
      }, timeoutMs);
      this.pending.push({ resolve, reject, timer });
      const message =
        payload === undefined ? JSON.stringify({ op }) : JSON.stringify({ op, payload });
      this.child.stdin.write(`${message}\n`);
    });
  }

  async stop() {
    if (this.readline) {
      this.readline.close();
      this.readline = null;
    }
    if (!this.child) {
      return;
    }
    this.child.stdin.end();
    const child = this.child;
    this.child = null;
    const exited = new Promise((resolve) => child.once("exit", resolve));
    const killTimer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 2_000);
    killTimer.unref?.();
    await exited.catch(() => {});
    clearTimeout(killTimer);
  }
}

async function main() {
  assert(fs.existsSync(workerPath), `Missing worker bundle: ${workerPath}. Run build:embedded-worker first.`);

  const temp = await makeTempRuntime();
  const env = {
    ...process.env,
    QYPHA_RUNTIME_HOME: temp.runtimeHome,
    QYPHA_RUNTIME_STATE_DIR: temp.runtimeState,
    QYPHA_RUNTIME_CONFIG_PATH: temp.runtimeConfig,
    QYPHA_EMBEDDED_DEBUG_LOG: temp.debugLogPath,
  };
  delete env.OPENCLAW_HOME;
  delete env.OPENCLAW_STATE_DIR;
  delete env.OPENCLAW_CONFIG_PATH;

  const worker = new WorkerSession({
    workerPath,
    runtimeRoot,
    env,
  });
  await worker.start();

  const report = {
    temp_root: temp.tempRoot,
    debug_log: temp.debugLogPath,
    passed: [],
    skipped: [],
    failed: [],
  };

  const memoryMetadata = {
    agent_name: "smoke-agent",
    session_id: "smoke-session",
  };

  const browserHtml = `<!doctype html>
<html>
  <body>
    <h1>Qypha Browser Smoke</h1>
    <a id="research-link" href="https://example.com/">Research Smoke Link</a>
    <button id="go" onclick="this.textContent='Clicked';document.getElementById('status').textContent='clicked'">Go</button>
    <div id="status">ready</div>
    <p>Research smoke token alpha beta gamma.</p>
  </body>
</html>`;
  const fixtureServer = await startFixtureServer(browserHtml);
  const htmlFixture = fixtureServer.url;
  const researchFixture = "https://example.com/";
  const researchBrowserFixture = htmlFixture;

  const textDocPath = path.join(temp.fixtureDir, "doc.txt");
  const osWritePath = path.join(temp.fixtureDir, "os-write.txt");
  const browserPdfPath = path.join(temp.fixtureDir, "browser-page.pdf");
  await fsp.writeFile(
    textDocPath,
    [
      "Qypha embedded runtime smoke document.",
      "Plugin MCP and OS capability validation file.",
      "Research smoke token alpha beta gamma.",
    ].join("\n"),
    "utf8",
  );

  let firstMemoryEntry = null;
  let compressedMemoryEntry = null;
  let browserSessionId = "browser-smoke";
  let researchSessionId = "research-smoke";
  let pluginCapabilityId = null;
  let repoOverview = null;

  async function runCase(name, fn, options = {}) {
    try {
      const detail = await fn();
      report.passed.push({ name, detail });
      process.stdout.write(`PASS ${name}\n`);
    } catch (error) {
      const message = normalizeError(error);
      if (options.optional) {
        report.skipped.push({ name, reason: message });
        process.stdout.write(`SKIP ${name}: ${message}\n`);
        return;
      }
      report.failed.push({ name, error: message });
      process.stdout.write(`FAIL ${name}: ${message}\n`);
    }
  }

  try {
    await runCase("worker.hello", async () => {
    const response = await worker.request("hello", undefined, 15_000);
    assert(response.ok === true, "hello response was not ok");
    assert(Array.isArray(response.capabilities), "hello response missing capabilities");
    return response;
    });

  await runCase("provider.healthcheck", async () => {
    const response = await worker.request("provider_healthcheck", {}, 15_000);
    assert(response.ok === true, "provider healthcheck failed");
    return response;
  });

  for (const provider of ["openai", "google", "anthropic"]) {
    await runCase(`provider.list_models.${provider}`, async () => {
      const response = await worker.request(
        "provider_list_models",
        { provider },
        20_000,
      );
      assert(response.ok === true, `${provider} model listing failed`);
      assert(Array.isArray(response.catalog) && response.catalog.length > 0, `${provider} catalog empty`);
      return { count: response.catalog.length };
    });
  }

  await runCase("provider.list_models.ollama", async () => {
    const response = await worker.request(
      "provider_list_models",
      { provider: "ollama" },
      20_000,
    );
    assert(response.ok === true, "ollama model listing failed");
    assert(Array.isArray(response.catalog), "ollama catalog missing");
    return { count: response.catalog.length };
  }, { optional: true });

  await runCase("memory.write", async () => {
    const content = "Qypha memory smoke line.\n".repeat(120);
    const response = await worker.request(
      "memory_write",
      {
        request: {
          actor_id: "smoke-agent",
          scope: "session",
          content,
          source_links: ["workspace://smoke#L1"],
        },
        metadata: memoryMetadata,
      },
      20_000,
    );
    assert(response.ok === true, "memory_write failed");
    assert(response.memory_entry?.memory_id, "memory_write did not return memory_id");
    firstMemoryEntry = response.memory_entry;
    return { memory_id: firstMemoryEntry.memory_id };
  });

  await runCase("memory.get", async () => {
    assert(firstMemoryEntry, "memory entry missing from previous step");
    const response = await worker.request(
      "memory_get",
      {
        request: {
          actor_id: "smoke-agent",
          memory_id: firstMemoryEntry.memory_id,
        },
        metadata: memoryMetadata,
      },
      15_000,
    );
    assert(response.ok === true, "memory_get failed");
    assert(response.memory_entry?.content?.includes("Qypha memory smoke line"), "memory_get content mismatch");
    return { memory_id: response.memory_entry.memory_id };
  });

  await runCase("memory.staleness", async () => {
    assert(firstMemoryEntry, "memory entry missing from previous step");
    const response = await worker.request(
      "memory_staleness_check",
      {
        request: {
          actor_id: "smoke-agent",
          memory_id: firstMemoryEntry.memory_id,
        },
        metadata: memoryMetadata,
      },
      15_000,
    );
    assert(response.ok === true, "memory staleness check failed");
    assert(response.stale === false, "fresh memory entry reported as stale");
    return response;
  });

  await runCase("memory.compress", async () => {
    const response = await worker.request(
      "memory_compress",
      {
        request: {
          actor_id: "smoke-agent",
          scope: "session",
        },
        metadata: memoryMetadata,
      },
      20_000,
    );
    assert(response.ok === true, "memory_compress failed");
    assert(response.memory_entry?.content?.includes("Compressed summary"), "memory_compress did not produce a summary");
    compressedMemoryEntry = response.memory_entry;
    return { memory_id: compressedMemoryEntry.memory_id };
  });

  await runCase("memory.search", async () => {
    let response = null;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      response = await worker.request(
        "memory_search",
        {
          request: {
            actor_id: "smoke-agent",
            query: "Qypha memory smoke line",
            limit: 3,
          },
          metadata: memoryMetadata,
        },
        20_000,
      );
      if (response.ok === true && Array.isArray(response.memory_entries) && response.memory_entries.length > 0) {
        break;
      }
      await delay(500);
    }
    assert(response?.ok === true, "memory_search failed");
    assert(Array.isArray(response.memory_entries) && response.memory_entries.length > 0, "memory_search returned no entries");
    return { count: response.memory_entries.length };
  });

  await runCase("repo.overview", async () => {
    const response = await worker.request(
      "repo_overview",
      {
        root: repoRoot,
      },
      20_000,
    );
    assert(response.ok === true, "repo_overview failed");
    assert(response.root === repoRoot, "repo_overview root mismatch");
    repoOverview = response;
    return { vcs: response.vcs ?? "none", dirty: response.dirty };
  });

  await runCase("repo.tree", async () => {
    const response = await worker.request(
      "repo_tree",
      {
        root: repoRoot,
        depth: 2,
      },
      30_000,
    );
    assert(response.ok === true, "repo_tree failed");
    assert(Array.isArray(response.entries) && response.entries.length > 0, "repo_tree returned no entries");
    return { count: response.entries.length };
  });

  await runCase("repo.grep", async () => {
    const response = await worker.request(
      "repo_grep",
      {
        root: repoRoot,
        pattern: "EmbeddedOpenClawMemoryRuntime",
        limit: 10,
      },
      30_000,
    );
    assert(response.ok === true, "repo_grep failed");
    assert(Array.isArray(response.repo_matches) && response.repo_matches.length > 0, "repo_grep returned no matches");
    return { count: response.repo_matches.length };
  });

  await runCase("repo.read_file", async () => {
    const response = await worker.request(
      "repo_read_file",
      {
        path: path.join(repoRoot, "src", "runtime", "embedded_openclaw.rs"),
      },
      20_000,
    );
    assert(response.ok === true, "repo_read_file failed");
    assert(typeof response.file_content === "string" && response.file_content.includes("EmbeddedOpenClawMemoryRuntime"), "repo_read_file content mismatch");
    return { bytes: response.file_content.length };
  });

  await runCase("repo.git_log", async () => {
    assert(repoOverview, "repo overview missing");
    if (!repoOverview.vcs) {
      throw new Error("workspace is not a git repository");
    }
    const response = await worker.request(
      "repo_git_log",
      {
        root: repoRoot,
        limit: 5,
      },
      20_000,
    );
    assert(response.ok === true, "repo_git_log failed");
    assert(Array.isArray(response.commits), "repo_git_log commits missing");
    return { count: response.commits.length };
  }, { optional: true });

  await runCase("repo.remote_inspect", async () => {
    const response = await worker.request(
      "repo_remote_inspect",
      {
        url: "https://github.com/openclaw/openclaw.git",
      },
      30_000,
    );
    assert(response.ok === true, "repo_remote_inspect failed");
    assert(typeof response.summary === "string" && response.summary.length > 0, "repo_remote_inspect summary missing");
    return { summary: response.summary };
  }, { optional: true });

  await runCase("os.read_text", async () => {
    const response = await worker.request(
      "os_execute",
      {
        request: {
          actor_id: "smoke-agent",
          access_mode: "restricted",
          execution_kind: "typed_operation",
          operation: {
            kind: "read_text",
            path: textDocPath,
          },
        },
      },
      20_000,
    );
    assert(response.ok === true && response.status === "completed", "os read_text did not complete");
    assert(response.stdout.includes("Qypha embedded runtime smoke document"), "os read_text output mismatch");
    return { bytes: response.stdout.length };
  });

  await runCase("os.write_text.blocked", async () => {
    const response = await worker.request(
      "os_execute",
      {
        request: {
          actor_id: "smoke-agent",
          access_mode: "restricted",
          execution_kind: "typed_operation",
          operation: {
            kind: "write_text",
            path: osWritePath,
            content: "should not write",
          },
        },
      },
      20_000,
    );
    assert(response.ok === true && response.status === "blocked", "restricted write_text should be blocked");
    return response;
  });

  await runCase("os.write_text.full_access", async () => {
    const response = await worker.request(
      "os_execute",
      {
        request: {
          actor_id: "smoke-agent",
          access_mode: "full_access",
          execution_kind: "typed_operation",
          operation: {
            kind: "write_text",
            path: osWritePath,
            content: "qypha os write smoke",
            create_parents: true,
          },
        },
      },
      20_000,
    );
    assert(response.ok === true && response.status === "completed", "full_access write_text failed");
    const written = await fsp.readFile(osWritePath, "utf8");
    assert(written === "qypha os write smoke", "os write_text file content mismatch");
    return response;
  });

  await runCase("os.list_dir", async () => {
    const response = await worker.request(
      "os_execute",
      {
        request: {
          actor_id: "smoke-agent",
          access_mode: "restricted",
          execution_kind: "typed_operation",
          operation: {
            kind: "list_dir",
            path: temp.fixtureDir,
          },
        },
      },
      20_000,
    );
    assert(response.ok === true && response.status === "completed", "os list_dir failed");
    assert(response.stdout.includes("doc.txt"), "os list_dir output missing fixture");
    return { paths: response.paths?.length ?? 0 };
  });

    await runCase("os.search_files", async () => {
    const response = await worker.request(
      "os_execute",
      {
        request: {
          actor_id: "smoke-agent",
          access_mode: "restricted",
          execution_kind: "typed_operation",
          operation: {
            kind: "search_files",
            root: temp.fixtureDir,
            pattern: "**/doc.txt",
          },
        },
      },
      25_000,
    );
    assert(response.ok === true && response.status === "completed", "os search_files failed");
    assert(response.stdout.includes("doc.txt") || response.paths?.some((entry) => entry.endsWith("doc.txt")), "os search_files did not locate the fixture");
    return { count: response.paths?.length ?? 0 };
  });

  await runCase("os.run_command", async () => {
    const response = await worker.request(
      "os_execute",
      {
        request: {
          actor_id: "smoke-agent",
          access_mode: "full_access",
          execution_kind: "typed_operation",
          operation: {
            kind: "run_command",
            command: {
              program: "/bin/echo",
              args: ["qypha-os-command-smoke"],
              cwd: temp.fixtureDir,
            },
          },
        },
      },
      20_000,
    );
    assert(response.ok === true && response.status === "completed", "os run_command failed");
    assert(response.stdout.includes("qypha-os-command-smoke"), "os run_command output mismatch");
    return response;
  });

  await runCase("browser.start_session", async () => {
    const response = await worker.request(
      "browser_start_session",
      {
        session_id: browserSessionId,
        mode: "persistent",
      },
      30_000,
    );
    assert(response.ok === true, "browser_start_session failed");
    return response;
  });

  await runCase("browser.open", async () => {
    const response = await worker.request(
      "browser_open",
      {
        session_id: browserSessionId,
        url: htmlFixture,
      },
      45_000,
    );
    assert(response.ok === true, "browser_open failed");
    assert(typeof response.markdown === "string" && response.markdown.includes("button \"Go\""), "browser_open snapshot missing actionable content");
    return { url: response.url };
  });

  await runCase("browser.interact", async () => {
    const response = await worker.request(
      "browser_interact",
      {
        session_id: browserSessionId,
        action: "click",
        target: "selector:#go",
      },
      45_000,
    );
    assert(response.ok === true, "browser_interact failed");
    assert(response.markdown.includes("button \"Clicked\""), "browser_interact did not update page state");
    return { url: response.url };
  });

  await runCase("browser.snapshot", async () => {
    const response = await worker.request(
      "browser_snapshot",
      {
        session_id: browserSessionId,
      },
      30_000,
    );
    assert(response.ok === true, "browser_snapshot failed");
    assert(response.markdown.includes("button \"Clicked\""), "browser_snapshot missing updated state");
    return { url: response.url };
  });

  await runCase("browser.download", async () => {
    const response = await worker.request(
      "browser_download",
      {
        session_id: browserSessionId,
        url: htmlFixture,
        destination: browserPdfPath,
      },
      45_000,
    );
    assert(response.ok === true, "browser_download failed");
    assert(fs.existsSync(browserPdfPath), "browser_download destination file missing");
    return { path: response.path };
  });

  await runCase("document.read.text", async () => {
    const response = await worker.request(
      "document_read",
      {
        path: textDocPath,
      },
      20_000,
    );
    assert(response.ok === true, "document_read text failed");
    assert(Array.isArray(response.sections) && response.sections.length > 0, "document_read text returned no sections");
    return { count: response.sections.length };
  });

  await runCase("document.read.pdf", async () => {
    const response = await worker.request(
      "document_read",
      {
        path: browserPdfPath,
      },
      45_000,
    );
    assert(response.ok === true, "document_read pdf failed");
    assert(Array.isArray(response.sections) && response.sections.length > 0, "document_read pdf returned no sections");
    const joined = response.sections.map((section) => section.body).join("\n");
    assert(joined.includes("Qypha Browser Smoke"), "document_read pdf missing rendered content");
    return { count: response.sections.length };
  });

  await runCase("plugin_mcp.list_plugins", async () => {
    const response = await worker.request("plugin_mcp_list_plugins", {}, 30_000);
    assert(response.ok === true, "plugin_mcp_list_plugins failed");
    assert(Array.isArray(response.plugins) && response.plugins.length > 0, "plugin_mcp_list_plugins returned no plugins");
    return { count: response.plugins.length };
  });

  await runCase("plugin_mcp.list_servers", async () => {
    const response = await worker.request("plugin_mcp_list_servers", {}, 30_000);
    assert(response.ok === true, "plugin_mcp_list_servers failed");
    assert(Array.isArray(response.servers) && response.servers.length > 0, "plugin_mcp_list_servers returned no servers");
    return { count: response.servers.length };
  });

  await runCase("plugin_mcp.resolve_capability", async () => {
    for (const candidate of ["read_text_file", "directory_tree", "search_files"]) {
      const response = await worker.request(
        "plugin_mcp_resolve_capability",
        {
          capability_id: candidate,
        },
        30_000,
      );
      if (response.ok === true && response.capability?.capability_id) {
        pluginCapabilityId = response.capability.capability_id;
        return response.capability;
      }
    }
    throw new Error("no known bundled MCP capability could be resolved");
  });

    await runCase("plugin_mcp.invoke", async () => {
    assert(pluginCapabilityId, "plugin capability missing");
    let argsJson = "{}";
    if (pluginCapabilityId.includes("read_text_file")) {
      argsJson = JSON.stringify({ path: textDocPath });
    } else if (pluginCapabilityId.includes("directory_tree")) {
      argsJson = JSON.stringify({ path: temp.fixtureDir });
    } else if (pluginCapabilityId.includes("search_files")) {
      argsJson = JSON.stringify({ path: temp.fixtureDir, pattern: "**/doc.txt" });
    }
    const response = await worker.request(
      "plugin_mcp_invoke",
      {
        capability_id: pluginCapabilityId,
        args_json: argsJson,
      },
      30_000,
    );
    assert(response.ok === true, "plugin_mcp_invoke failed");
    assert(typeof response.output_json === "string" && response.output_json.length > 0, "plugin_mcp_invoke output missing");
    assert(!response.output_json.includes("Access denied"), "plugin_mcp_invoke returned access denial");
    if (pluginCapabilityId.includes("read_text_file")) {
      assert(response.output_json.includes("Qypha embedded runtime smoke document"), "plugin_mcp_invoke did not read the fixture content");
    } else {
      assert(response.output_json.includes("doc.txt"), "plugin_mcp_invoke did not locate the fixture path");
    }
    return { capability_id: pluginCapabilityId };
  });

    await runCase("research.inspect", async () => {
    const response = await worker.request(
      "research_inspect",
      {
        provider: "openai",
        model_id: "gpt-5.4",
        query: "example domain",
        sources: [
          {
            title: "Example Domain",
            url: researchFixture,
            snippet: "Example Domain is for illustrative examples in documents.",
          },
        ],
        max_sources: 1,
      },
      45_000,
    );
    assert(response.ok === true, "research_inspect failed");
    assert(Array.isArray(response.inspected_sources) && response.inspected_sources.length > 0, "research_inspect returned no inspected sources");
    return { count: response.inspected_sources.length };
  });

    await runCase("research.open_page", async () => {
    const response = await worker.request(
      "research_open_page",
      {
        session_id: researchSessionId,
        source: {
          title: "Research Smoke Fixture",
          url: researchBrowserFixture,
          snippet: "Research Smoke Link appears as the accessible link text on the page.",
        },
      },
      45_000,
    );
    assert(response.ok === true, "research_open_page failed");
    assert(typeof response.markdown === "string" && response.markdown.includes("Research Smoke Link"), "research_open_page snapshot missing expected text");
    return { url: response.url };
    });

    await runCase("research.find_in_page", async () => {
    const response = await worker.request(
      "research_find_in_page",
      {
        session_id: researchSessionId,
        query: "Research Smoke Link",
        source: {
          title: "Research Smoke Fixture",
          url: researchBrowserFixture,
        },
        max_matches: 5,
      },
      45_000,
    );
    assert(response.ok === true, "research_find_in_page failed");
    assert(Array.isArray(response.matches) && response.matches.length > 0, "research_find_in_page returned no matches");
    return { count: response.matches.length };
  });

    await runCase("research.search", async () => {
    const response = await worker.request(
      "research_search",
      {
        provider: "openai",
        model_id: "gpt-5.4",
        query: "qypha embedded runtime",
        max_results: 3,
      },
      45_000,
    );
    assert(response.ok === true, "research_search failed");
    assert(Array.isArray(response.sources) && response.sources.length > 0, "research_search returned no sources");
    return { count: response.sources.length };
  }, { optional: true });

  const authGenerateCandidates = [
    process.env.OPENAI_API_KEY
      ? { provider: "openai", model_id: "gpt-5.4-mini" }
      : null,
    process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY
      ? { provider: "google", model_id: "gemini-3.1-flash" }
      : null,
    process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_OAUTH_TOKEN
      ? { provider: "anthropic", model_id: "claude-sonnet-4-6" }
      : null,
  ].filter(Boolean);

  const providerGenerateCandidate = authGenerateCandidates[0] ?? null;

    await runCase("provider.generate", async () => {
    if (!providerGenerateCandidate) {
      throw new Error("no provider credentials detected");
    }
    const response = await worker.request(
      "provider_generate",
      {
        provider: providerGenerateCandidate.provider,
        model_id: providerGenerateCandidate.model_id,
        messages: [{ role: "user", content: "Reply with exactly: qypha-provider-smoke" }],
      },
      90_000,
    );
    assert(response.ok === true, "provider_generate failed");
    assert(response.output_text.toLowerCase().includes("qypha-provider-smoke"), "provider_generate output mismatch");
    return { model_id: response.model_id };
  }, { optional: true });

    await runCase("research.plan", async () => {
    if (!providerGenerateCandidate) {
      throw new Error("no provider credentials detected");
    }
    const response = await worker.request(
      "research_plan",
      {
        provider: providerGenerateCandidate.provider,
        model_id: providerGenerateCandidate.model_id,
        query: "What changed in the latest qypha runtime build pipeline?",
        local_context_available: true,
      },
      90_000,
    );
    assert(response.ok === true, "research_plan failed");
    assert(typeof response.disposition === "string", "research_plan disposition missing");
    return { disposition: response.disposition };
  }, { optional: true });

    await runCase("research.synthesize", async () => {
    if (!providerGenerateCandidate) {
      throw new Error("no provider credentials detected");
    }
    const response = await worker.request(
      "research_synthesize",
      {
        provider: providerGenerateCandidate.provider,
        model_id: providerGenerateCandidate.model_id,
        query: "Summarize the browser smoke fixture.",
        inspected_sources: [
          {
            source: {
              title: "Research Browser Smoke",
              url: researchFixture,
            },
            summary: "Qypha Browser Smoke page contains a button and a research smoke token.",
            extracted_text: "Qypha Browser Smoke clicked Research smoke token alpha beta gamma.",
          },
        ],
      },
      90_000,
    );
    assert(response.ok === true, "research_synthesize failed");
    assert(typeof response.output_text === "string" && response.output_text.length > 0, "research_synthesize output missing");
    return { chars: response.output_text.length };
  }, { optional: true });

    await runCase("agent.run", async () => {
    if (!providerGenerateCandidate) {
      throw new Error("no provider credentials detected");
    }
    const response = await worker.request(
      "agent_run",
      {
        provider: providerGenerateCandidate.provider,
        model_id: providerGenerateCandidate.model_id,
        prompt: "Reply with exactly: qypha-agent-smoke",
        metadata: {
          agent_name: "smoke-agent",
          session_id: "agent-smoke-session",
        },
      },
      120_000,
    );
    assert(response.ok === true, "agent_run failed");
    assert(response.output_text.toLowerCase().includes("qypha-agent-smoke"), "agent_run output mismatch");
    return { finish_reason: response.finish_reason ?? "unknown" };
  }, { optional: true });

  } finally {
    await worker.stop();
    await fixtureServer.close().catch(() => {});
  }

  const summary = {
    passed: report.passed.length,
    skipped: report.skipped.length,
    failed: report.failed.length,
    temp_root: report.temp_root,
    debug_log: report.debug_log,
  };
  process.stdout.write(`\nSummary ${JSON.stringify(summary, null, 2)}\n`);
  if (report.skipped.length > 0) {
    process.stdout.write(`Skipped ${JSON.stringify(report.skipped, null, 2)}\n`);
  }
  if (report.failed.length > 0) {
    process.stdout.write(`Failed ${JSON.stringify(report.failed, null, 2)}\n`);
    process.exitCode = 1;
  }
}

await main();

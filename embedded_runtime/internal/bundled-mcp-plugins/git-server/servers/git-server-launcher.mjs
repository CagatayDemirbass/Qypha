import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolveBundledPythonExecutable } from "../../../runtime/python/managed-python.mjs";
import {
  resolveBundledGitBinDir,
  resolveBundledGitExecutable,
} from "../../../runtime/git/managed-git.mjs";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sitePackages = path.resolve(pluginRoot, "vendor", "site-packages");
const bundledGitExecutable = resolveBundledGitExecutable();
const bundledGitBinDir = resolveBundledGitBinDir();

function resolvePythonLauncher() {
  const bundledPython = resolveBundledPythonExecutable();
  const configured = process.env.QYPHA_PYTHON_BIN?.trim();
  const candidates = [
    ...(bundledPython && fs.existsSync(bundledPython)
      ? [{ command: bundledPython, prefixArgs: [] }]
      : []),
    ...(configured ? [{ command: configured, prefixArgs: [] }] : []),
    ...(process.platform === "win32"
      ? [
          { command: "C:\\Windows\\py.exe", prefixArgs: ["-3"] },
          { command: "py", prefixArgs: ["-3"] },
          { command: "python", prefixArgs: [] },
          { command: "python3", prefixArgs: [] },
        ]
      : [
          { command: "/opt/homebrew/bin/python3", prefixArgs: [] },
          { command: "/usr/local/bin/python3", prefixArgs: [] },
          { command: "/usr/bin/python3", prefixArgs: [] },
          { command: "python3", prefixArgs: [] },
          { command: "python", prefixArgs: [] },
        ]),
  ];
  for (const candidate of candidates) {
    const probe = spawnSync(
      candidate.command,
      [...candidate.prefixArgs, "-c", "import sys; print(sys.executable)"],
      {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    if (probe.status === 0 && probe.stdout.trim()) {
      return candidate;
    }
  }
  throw new Error(
    "Unable to locate a Python runtime. Run `npm run bootstrap:bundled-python` in embedded_runtime or set QYPHA_PYTHON_BIN.",
  );
}

function joinPythonPath(existingPath, extraPath) {
  if (!existingPath?.trim()) {
    return extraPath;
  }
  return `${extraPath}${path.delimiter}${existingPath}`;
}

function prependPath(existingPath, extraPath) {
  if (!extraPath?.trim()) {
    return existingPath;
  }
  if (!existingPath?.trim()) {
    return extraPath;
  }
  return `${extraPath}${path.delimiter}${existingPath}`;
}

const python = resolvePythonLauncher();
const child = spawn(
  python.command,
  [...python.prefixArgs, "-m", "mcp_server_git", ...process.argv.slice(2)],
  {
    cwd: pluginRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      PYTHONPATH: joinPythonPath(process.env.PYTHONPATH, sitePackages),
      PATH:
        bundledGitBinDir && fs.existsSync(bundledGitBinDir)
          ? prependPath(process.env.PATH, bundledGitBinDir)
          : process.env.PATH,
      ...(bundledGitExecutable && fs.existsSync(bundledGitExecutable)
        ? {
            GIT_PYTHON_GIT_EXECUTABLE: bundledGitExecutable,
            GIT_PYTHON_REFRESH: "quiet",
          }
        : {}),
    },
  },
);

child.on("error", (error) => {
  console.error(String(error));
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});

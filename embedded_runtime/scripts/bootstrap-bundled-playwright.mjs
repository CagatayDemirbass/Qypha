import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const args = new Set(process.argv.slice(2));
const quiet = args.has("--quiet");
const force = args.has("--force");

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const runtimeRoot = path.resolve(scriptDir, "..");
const playwrightVendorRoot = path.resolve(
  runtimeRoot,
  "internal",
  "bundled-mcp-plugins",
  "playwright-mcp",
  "vendor",
);
const playwrightPackageRoot = path.resolve(
  playwrightVendorRoot,
  "playwright-mcp",
  "package",
);
const playwrightPackageJsonPath = path.resolve(playwrightPackageRoot, "package.json");
const playwrightCliPath = path.resolve(
  playwrightVendorRoot,
  "node_modules",
  "playwright",
  "cli.js",
);
const browsersPath = path.resolve(
  playwrightVendorRoot,
  "ms-playwright",
);

function fail(message) {
  throw new Error(message);
}

function log(message) {
  if (!quiet) {
    console.log(message);
  }
}

function resolveNpmCommand() {
  const npmExecPath = process.env.npm_execpath?.trim();
  if (npmExecPath) {
    const lowerPath = npmExecPath.toLowerCase();
    if (lowerPath.endsWith(".js") || lowerPath.endsWith(".cjs") || lowerPath.endsWith(".mjs")) {
      return {
        command: process.execPath,
        prefixArgs: [npmExecPath],
      };
    }
    return {
      command: npmExecPath,
      prefixArgs: [],
    };
  }

  return {
    command: process.platform === "win32" ? "npm.cmd" : "npm",
    prefixArgs: [],
  };
}

async function runCommand(command, commandArgs, options = {}) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, {
      stdio: quiet ? ["ignore", "pipe", "pipe"] : "inherit",
      ...options,
    });
    let stderr = "";
    let stdout = "";
    if (quiet) {
      child.stdout?.on("data", (chunk) => {
        stdout += chunk.toString();
      });
      child.stderr?.on("data", (chunk) => {
        stderr += chunk.toString();
      });
    }
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `Playwright bootstrap failed (${signal || code}). ${stderr.trim() || stdout.trim()}`,
        ),
      );
    });
  });
}

async function readJson(filePath) {
  return JSON.parse(await fsp.readFile(filePath, "utf-8"));
}

async function ensurePlaywrightVendorDependencies() {
  if (!fs.existsSync(playwrightPackageJsonPath)) {
    fail(`Bundled Playwright package metadata missing at ${playwrightPackageJsonPath}`);
  }

  const packageJson = await readJson(playwrightPackageJsonPath);
  const expectedPlaywrightVersion = packageJson.dependencies?.playwright;
  const expectedPlaywrightCoreVersion = packageJson.dependencies?.["playwright-core"];

  if (!expectedPlaywrightVersion || !expectedPlaywrightCoreVersion) {
    fail(`Bundled Playwright package at ${playwrightPackageJsonPath} is missing pinned dependencies`);
  }

  const installedPlaywrightManifestPath = path.resolve(
    playwrightVendorRoot,
    "node_modules",
    "playwright",
    "package.json",
  );
  const installedPlaywrightCoreManifestPath = path.resolve(
    playwrightVendorRoot,
    "node_modules",
    "playwright-core",
    "package.json",
  );

  if (
    !force &&
    fs.existsSync(installedPlaywrightManifestPath) &&
    fs.existsSync(installedPlaywrightCoreManifestPath)
  ) {
    try {
      const installedPlaywright = await readJson(installedPlaywrightManifestPath);
      const installedPlaywrightCore = await readJson(installedPlaywrightCoreManifestPath);
      if (
        installedPlaywright.version === expectedPlaywrightVersion &&
        installedPlaywrightCore.version === expectedPlaywrightCoreVersion
      ) {
        log("Bundled Playwright npm dependencies already installed");
        return;
      }
    } catch {
      // reinstall below if manifests are unreadable
    }
  }

  log("Installing bundled Playwright npm dependencies");
  await fsp.mkdir(playwrightVendorRoot, { recursive: true });
  await fsp.rm(path.resolve(playwrightVendorRoot, "node_modules"), {
    recursive: true,
    force: true,
  });
  const npmCommand = resolveNpmCommand();
  await runCommand(
    npmCommand.command,
    [
      ...npmCommand.prefixArgs,
      "install",
      "--prefix",
      playwrightVendorRoot,
      "--no-save",
      "--package-lock=false",
      "--ignore-scripts",
      `playwright@${expectedPlaywrightVersion}`,
      `playwright-core@${expectedPlaywrightCoreVersion}`,
    ],
    {
      env: {
        ...process.env,
        PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1",
        npm_config_audit: "false",
        npm_config_fund: "false",
      },
    },
  );
}

await ensurePlaywrightVendorDependencies();
await runCommand(process.execPath, [playwrightCliPath, "install", "chromium"], {
  env: {
    ...process.env,
    PLAYWRIGHT_BROWSERS_PATH: browsersPath,
  },
});

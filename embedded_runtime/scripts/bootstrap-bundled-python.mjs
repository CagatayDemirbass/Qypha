import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import * as tar from "tar";
import {
  buildBundledPythonChecksumUrl,
  buildBundledPythonDownloadUrl,
  bundledPythonRelease,
  resolveBundledPythonArchivePath,
  resolveBundledPythonExecutable,
  resolveBundledPythonInstallDir,
  resolveBundledPythonTarget,
} from "../internal/runtime/python/managed-python.mjs";

const args = new Set(process.argv.slice(2));
const quiet = args.has("--quiet");
const force = args.has("--force");
const printBin = args.has("--print-bin");
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const runtimeRoot = path.resolve(scriptDir, "..");

const pythonVendorPlugins = [
  {
    name: "git-server",
    pluginRoot: path.resolve(
      runtimeRoot,
      "internal",
      "bundled-mcp-plugins",
      "git-server",
    ),
  },
  {
    name: "fetch-server",
    pluginRoot: path.resolve(
      runtimeRoot,
      "internal",
      "bundled-mcp-plugins",
      "fetch-server",
    ),
  },
];
const bundledDocgenRequirementsPath = path.resolve(
  runtimeRoot,
  "scripts",
  "bundled-python-docgen-requirements.txt",
);

function log(message) {
  if (!quiet) {
    console.log(message);
  }
}

function fail(message) {
  throw new Error(message);
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
          `${command} ${commandArgs.join(" ")} failed (${signal || code}). ${
            stderr.trim() || stdout.trim()
          }`,
        ),
      );
    });
  });
}

async function fetchText(url) {
  const response = await fetch(url, {
    headers: {
      "user-agent": "qypha-bundled-python-bootstrap",
      accept: "text/plain, application/json;q=0.9, */*;q=0.8",
    },
  });
  if (!response.ok) {
    fail(`Failed to fetch ${url} (${response.status} ${response.statusText})`);
  }
  return await response.text();
}

async function downloadToFile(url, destination) {
  const response = await fetch(url, {
    headers: {
      "user-agent": "qypha-bundled-python-bootstrap",
      accept: "application/octet-stream, */*;q=0.8",
    },
  });
  if (!response.ok || !response.body) {
    fail(`Failed to download ${url} (${response.status} ${response.statusText})`);
  }
  await fsp.mkdir(path.dirname(destination), { recursive: true });
  const tempPath = `${destination}.tmp-${process.pid}-${Date.now()}`;
  const file = fs.createWriteStream(tempPath);
  const bodyStream = Readable.fromWeb(response.body);
  await new Promise((resolve, reject) => {
    bodyStream.pipe(file);
    bodyStream.on("error", reject);
    file.on("error", reject);
    file.on("finish", resolve);
  });
  await fsp.rename(tempPath, destination);
}

async function sha256File(filePath) {
  return await new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function sha256Text(text) {
  return createHash("sha256").update(text).digest("hex");
}

function parseChecksumMap(raw) {
  const result = new Map();
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const match = trimmed.match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (!match) {
      continue;
    }
    result.set(match[2], match[1].toLowerCase());
  }
  return result;
}

async function ensureArchive(downloadUrl, archivePath, expectedSha) {
  if (!force && fs.existsSync(archivePath)) {
    const actualSha = await sha256File(archivePath);
    if (actualSha === expectedSha) {
      log(`Bundled Python archive cache hit: ${path.basename(archivePath)}`);
      return;
    }
    await fsp.rm(archivePath, { force: true });
  }
  log(`Downloading bundled Python: ${downloadUrl}`);
  await downloadToFile(downloadUrl, archivePath);
  const actualSha = await sha256File(archivePath);
  if (actualSha !== expectedSha) {
    await fsp.rm(archivePath, { force: true });
    fail(
      `Checksum mismatch for ${path.basename(archivePath)} (expected ${expectedSha}, got ${actualSha})`,
    );
  }
}

async function extractArchive(archivePath, installDir, executablePath, target) {
  const installParent = path.dirname(installDir);
  const stagingDir = path.resolve(
    installParent,
    `${target.key}.staging-${process.pid}-${Date.now()}`,
  );
  await fsp.rm(stagingDir, { recursive: true, force: true });
  await fsp.mkdir(stagingDir, { recursive: true });
  await tar.x({
    file: archivePath,
    cwd: stagingDir,
    gzip: true,
    strict: true,
  });
  const stagedExecutable =
    process.platform === "win32"
      ? path.resolve(stagingDir, "python", "python.exe")
      : path.resolve(stagingDir, "python", "bin", "python3");
  if (!fs.existsSync(stagedExecutable)) {
    await fsp.rm(stagingDir, { recursive: true, force: true });
    fail(`Bundled Python archive did not contain ${path.relative(stagingDir, stagedExecutable)}`);
  }
  await fsp.rm(installDir, { recursive: true, force: true });
  await fsp.rename(stagingDir, installDir);
  const metadataPath = path.resolve(installDir, ".qypha-python.json");
  await fsp.writeFile(
    metadataPath,
    JSON.stringify(
      {
        release_tag: bundledPythonRelease.tag,
        python_version: bundledPythonRelease.pythonVersion,
        asset_name: target.assetName,
        installed_at: new Date().toISOString(),
        executable: executablePath,
      },
      null,
      2,
    ),
  );
}

async function ensureVendoredPythonPackages(executablePath) {
  for (const plugin of pythonVendorPlugins) {
    const vendorRoot = path.resolve(plugin.pluginRoot, "vendor");
    const sitePackagesDir = path.resolve(vendorRoot, "site-packages");
    const lockPath = path.resolve(vendorRoot, "requirements-lock.txt");
    const sourcePath = path.resolve(plugin.pluginRoot, "upstream");
    const stampPath = path.resolve(vendorRoot, ".qypha-python-vendor.json");
    const lockContents = await fsp.readFile(lockPath, "utf-8");
    const lockHash = sha256Text(lockContents);

    if (!force && fs.existsSync(stampPath) && fs.existsSync(sitePackagesDir)) {
      try {
        const stamp = JSON.parse(await fsp.readFile(stampPath, "utf-8"));
        if (
          stamp?.release_tag === bundledPythonRelease.tag &&
          stamp?.python_version === bundledPythonRelease.pythonVersion &&
          stamp?.lock_hash === lockHash
        ) {
          log(`Bundled Python packages already installed for ${plugin.name}`);
          continue;
        }
      } catch {
        // Reinstall when the stamp cannot be parsed.
      }
    }

    log(`Installing bundled Python packages for ${plugin.name}`);
    await fsp.rm(sitePackagesDir, { recursive: true, force: true });
    await fsp.mkdir(sitePackagesDir, { recursive: true });

    await runCommand(
      executablePath,
      [
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--no-compile",
        "--target",
        sitePackagesDir,
        "-r",
        lockPath,
      ],
      {
        cwd: plugin.pluginRoot,
        env: {
          ...process.env,
          PIP_DISABLE_PIP_VERSION_CHECK: "1",
        },
      },
    );

    await runCommand(
      executablePath,
      [
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--no-compile",
        "--no-deps",
        "--target",
        sitePackagesDir,
        sourcePath,
      ],
      {
        cwd: plugin.pluginRoot,
        env: {
          ...process.env,
          PIP_DISABLE_PIP_VERSION_CHECK: "1",
        },
      },
    );

    await fsp.writeFile(
      stampPath,
      JSON.stringify(
        {
          release_tag: bundledPythonRelease.tag,
          python_version: bundledPythonRelease.pythonVersion,
          lock_hash: lockHash,
          updated_at: new Date().toISOString(),
        },
        null,
        2,
      ),
    );
  }
}

async function ensureDocumentGenerationPackages(executablePath) {
  if (!fs.existsSync(bundledDocgenRequirementsPath)) {
    return;
  }
  const requirementsRaw = await fsp.readFile(bundledDocgenRequirementsPath, "utf-8");
  const requirementsHash = sha256Text(requirementsRaw);
  const installDir = resolveBundledPythonInstallDir();
  if (!installDir) {
    fail("Bundled Python install directory could not be resolved for document generation packages.");
  }
  const stampPath = path.resolve(installDir, ".qypha-python-docgen.json");
  if (!force && fs.existsSync(stampPath)) {
    try {
      const stamp = JSON.parse(await fsp.readFile(stampPath, "utf-8"));
      if (
        stamp?.release_tag === bundledPythonRelease.tag &&
        stamp?.python_version === bundledPythonRelease.pythonVersion &&
        stamp?.requirements_hash === requirementsHash
      ) {
        log("Bundled Python document generation packages already installed");
        return;
      }
    } catch {
      // Reinstall below when the stamp cannot be parsed.
    }
  }

  log("Installing bundled Python document generation packages");
  await runCommand(
    executablePath,
    [
      "-m",
      "pip",
      "install",
      "--upgrade",
      "--no-compile",
      "-r",
      bundledDocgenRequirementsPath,
    ],
    {
      cwd: runtimeRoot,
      env: {
        ...process.env,
        PIP_DISABLE_PIP_VERSION_CHECK: "1",
      },
    },
  );

  await fsp.writeFile(
    stampPath,
    JSON.stringify(
      {
        release_tag: bundledPythonRelease.tag,
        python_version: bundledPythonRelease.pythonVersion,
        requirements_hash: requirementsHash,
        updated_at: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
}

async function main() {
  const target = resolveBundledPythonTarget();
  if (!target) {
    fail(
      `No bundled Python target for ${process.platform}/${process.arch}. Set QYPHA_BUNDLED_PYTHON_TARGET if you need a manual override.`,
    );
  }
  const installDir = resolveBundledPythonInstallDir();
  const executablePath = resolveBundledPythonExecutable();
  const archivePath = resolveBundledPythonArchivePath();
  const downloadUrl = buildBundledPythonDownloadUrl();
  if (!installDir || !executablePath || !archivePath || !downloadUrl) {
    fail("Bundled Python paths could not be resolved.");
  }

  if (!force && fs.existsSync(executablePath)) {
    log(`Bundled Python already installed: ${executablePath}`);
  } else {
    const checksumText = await fetchText(buildBundledPythonChecksumUrl());
    const checksums = parseChecksumMap(checksumText);
    const expectedSha = checksums.get(target.assetName);
    if (!expectedSha) {
      fail(`SHA256SUMS did not contain ${target.assetName}`);
    }

    await ensureArchive(downloadUrl, archivePath, expectedSha);
    log(`Extracting bundled Python into ${installDir}`);
    await fsp.mkdir(path.dirname(installDir), { recursive: true });
    await extractArchive(archivePath, installDir, executablePath, target);
  }
  await ensureVendoredPythonPackages(executablePath);
  await ensureDocumentGenerationPackages(executablePath);

  if (printBin) {
    console.log(executablePath);
  } else {
    log(`Bundled Python ready: ${executablePath}`);
  }
}

await main();

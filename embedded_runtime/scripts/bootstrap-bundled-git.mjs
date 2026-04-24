import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import {
  buildBundledGitMicromambaUrl,
  bundledGitRelease,
  resolveBundledGitArchivePath,
  resolveBundledGitBinDir,
  resolveBundledGitExecutable,
  resolveBundledGitMicromambaExecutable,
  resolveBundledGitPrefix,
  resolveBundledGitRootDir,
  resolveBundledGitTarget,
} from "../internal/runtime/git/managed-git.mjs";
import { resolveBundledPythonExecutable } from "../internal/runtime/python/managed-python.mjs";

const args = new Set(process.argv.slice(2));
const quiet = args.has("--quiet");
const force = args.has("--force");
const printBin = args.has("--print-bin");

function log(message) {
  if (!quiet) {
    console.log(message);
  }
}

function fail(message) {
  throw new Error(message);
}

function resolveTargetRuntimePlatformArch(target) {
  const [platform, arch] = target.key.split("-");
  return { platform, arch };
}

function shouldFallbackDirectoryInstall(error) {
  return ["EPERM", "EACCES", "EBUSY", "ENOTEMPTY", "EXDEV", "UNKNOWN"].includes(
    error?.code,
  );
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function installStagedDirectory(stagingDir, destinationDir) {
  await fsp.mkdir(path.dirname(destinationDir), { recursive: true });
  await fsp.rm(destinationDir, { recursive: true, force: true });

  let lastRenameError;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await fsp.rename(stagingDir, destinationDir);
      return;
    } catch (error) {
      lastRenameError = error;
      if (!shouldFallbackDirectoryInstall(error) || attempt === 4) {
        break;
      }
      await sleep(250 * (attempt + 1));
    }
  }

  if (lastRenameError && !shouldFallbackDirectoryInstall(lastRenameError)) {
    throw lastRenameError;
  }

  await fsp.rm(destinationDir, { recursive: true, force: true });
  await fsp.cp(stagingDir, destinationDir, { recursive: true, force: true });
  await fsp.rm(stagingDir, { recursive: true, force: true });
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

async function downloadToFile(url, destination) {
  const response = await fetch(url, {
    headers: {
      "user-agent": "qypha-bundled-git-bootstrap",
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

function bundledGitArchiveSha(target) {
  return target.portableGitSha256 || target.micromambaSha256;
}

async function ensureGitArchive(target, archivePath, downloadUrl) {
  const expectedSha = bundledGitArchiveSha(target);
  if (!force && fs.existsSync(archivePath)) {
    const actualSha = await sha256File(archivePath);
    if (!expectedSha || actualSha === expectedSha) {
      log(`Bundled git archive cache hit: ${path.basename(archivePath)}`);
      return;
    }
    await fsp.rm(archivePath, { force: true });
  }
  log(`Downloading bundled git runtime: ${downloadUrl}`);
  await downloadToFile(downloadUrl, archivePath);
  if (!expectedSha) {
    return;
  }
  const actualSha = await sha256File(archivePath);
  if (actualSha !== expectedSha) {
    await fsp.rm(archivePath, { force: true });
    fail(
      `Checksum mismatch for ${path.basename(archivePath)} (expected ${expectedSha}, got ${actualSha})`,
    );
  }
}

async function ensureMicromamba(target, rootDir, archivePath) {
  const { platform, arch } = resolveTargetRuntimePlatformArch(target);
  const executablePath = resolveBundledGitMicromambaExecutable(platform, arch);
  if (!force && executablePath && fs.existsSync(executablePath)) {
    return executablePath;
  }
  const bundledPython = resolveBundledPythonExecutable();
  if (!bundledPython || !fs.existsSync(bundledPython)) {
    fail(
      "Bundled Python is required to extract the micromamba archive. Run `npm run bootstrap:bundled-python` first.",
    );
  }
  const micromambaDir = path.resolve(rootDir, "micromamba");
  const stagingDir = path.resolve(
    rootDir,
    `micromamba.staging-${process.pid}-${Date.now()}`,
  );
  await fsp.rm(stagingDir, { recursive: true, force: true });
  await fsp.mkdir(stagingDir, { recursive: true });
  await runCommand(
    bundledPython,
    [
      "-c",
      [
        "import pathlib, sys, tarfile",
        "archive = pathlib.Path(sys.argv[1])",
        "target = pathlib.Path(sys.argv[2])",
        "tf = tarfile.open(archive, 'r:bz2')",
        "tf.extractall(target)",
        "tf.close()",
      ].join("; "),
      archivePath,
      stagingDir,
    ],
  );
  await installStagedDirectory(stagingDir, micromambaDir);
  const resolvedExecutable = resolveBundledGitMicromambaExecutable(platform, arch);
  if (!resolvedExecutable || !fs.existsSync(resolvedExecutable)) {
    fail(`Bundled micromamba executable missing for ${target.key}`);
  }
  return resolvedExecutable;
}

async function ensurePortableGitPrefix(target, rootDir, archivePath) {
  const { platform, arch } = resolveTargetRuntimePlatformArch(target);
  const prefix = resolveBundledGitPrefix(platform, arch);
  const gitExecutable = resolveBundledGitExecutable(platform, arch);
  const gitBinDir = resolveBundledGitBinDir(platform, arch);
  if (!prefix || !gitExecutable || !gitBinDir) {
    fail("Bundled git paths could not be resolved.");
  }
  const metadataPath = path.resolve(rootDir, ".qypha-git.json");
  if (!force && fs.existsSync(gitExecutable) && fs.existsSync(metadataPath)) {
    try {
      const metadata = JSON.parse(await fsp.readFile(metadataPath, "utf-8"));
      if (
        metadata?.portable_git_asset === target.portableGitAsset &&
        metadata?.windows_release_tag === bundledGitRelease.windowsReleaseTag
      ) {
        return gitExecutable;
      }
    } catch {
      // reinstall below
    }
  }

  const bundledPython = resolveBundledPythonExecutable();
  if (!bundledPython || !fs.existsSync(bundledPython)) {
    fail(
      "Bundled Python is required to extract the portable Git archive. Run `npm run bootstrap:bundled-python` first.",
    );
  }

  const stagingDir = path.resolve(
    rootDir,
    `prefix.staging-${process.pid}-${Date.now()}`,
  );
  await fsp.rm(stagingDir, { recursive: true, force: true });
  await fsp.mkdir(stagingDir, { recursive: true });
  await runCommand(
    bundledPython,
    [
      "-c",
      [
        "import pathlib, sys, zipfile",
        "archive = pathlib.Path(sys.argv[1])",
        "target = pathlib.Path(sys.argv[2])",
        "zf = zipfile.ZipFile(archive, 'r')",
        "zf.extractall(target)",
        "zf.close()",
      ].join("; "),
      archivePath,
      stagingDir,
    ],
  );

  await installStagedDirectory(stagingDir, prefix);

  if (!fs.existsSync(gitExecutable)) {
    fail(`Bundled git executable missing after bootstrap: ${gitExecutable}`);
  }

  await fsp.writeFile(
    metadataPath,
    JSON.stringify(
      {
        target: target.key,
        portable_git_asset: target.portableGitAsset,
        windows_release_tag: bundledGitRelease.windowsReleaseTag,
        installed_at: new Date().toISOString(),
        git_executable: gitExecutable,
      },
      null,
      2,
    ),
  );

  return gitExecutable;
}

async function ensureGitPrefix(target, rootDir, micromambaPath) {
  const { platform, arch } = resolveTargetRuntimePlatformArch(target);
  const prefix = resolveBundledGitPrefix(platform, arch);
  const gitExecutable = resolveBundledGitExecutable(platform, arch);
  const gitBinDir = resolveBundledGitBinDir(platform, arch);
  if (!prefix || !gitExecutable || !gitBinDir) {
    fail("Bundled git paths could not be resolved.");
  }
  const metadataPath = path.resolve(rootDir, ".qypha-git.json");
  if (!force && fs.existsSync(gitExecutable) && fs.existsSync(metadataPath)) {
    try {
      const metadata = JSON.parse(await fsp.readFile(metadataPath, "utf-8"));
      if (
        metadata?.git_spec === bundledGitRelease.gitSpec &&
        metadata?.micromamba_version === bundledGitRelease.micromambaVersion
      ) {
        return gitExecutable;
      }
    } catch {
      // reinstall below
    }
  }

  await fsp.mkdir(rootDir, { recursive: true });
  const rootPrefix = path.resolve(rootDir, "mamba-root");
  const pkgsDir = path.resolve(rootDir, "pkgs");
  await runCommand(
    micromambaPath,
    [
      "create",
      "--yes",
      "--root-prefix",
      rootPrefix,
      "--prefix",
      prefix,
      "--override-channels",
      "--channel",
      "conda-forge",
      bundledGitRelease.gitSpec,
    ],
    {
      env: {
        ...process.env,
        MAMBA_ROOT_PREFIX: rootPrefix,
        CONDA_PKGS_DIRS: pkgsDir,
      },
    },
  );

  if (!fs.existsSync(gitExecutable)) {
    fail(`Bundled git executable missing after bootstrap: ${gitExecutable}`);
  }

  await fsp.writeFile(
    metadataPath,
    JSON.stringify(
      {
        target: target.key,
        conda_subdir: target.condaSubdir,
        git_spec: bundledGitRelease.gitSpec,
        micromamba_version: bundledGitRelease.micromambaVersion,
        installed_at: new Date().toISOString(),
        git_executable: gitExecutable,
      },
      null,
      2,
    ),
  );
  return gitExecutable;
}

async function main() {
  const target = resolveBundledGitTarget();
  if (!target) {
    fail(
      `No bundled git target for ${process.platform}/${process.arch}. Set QYPHA_BUNDLED_GIT_TARGET if you need a manual override.`,
    );
  }
  const rootDir = resolveBundledGitRootDir();
  const archivePath = resolveBundledGitArchivePath();
  const downloadUrl = buildBundledGitMicromambaUrl();
  if (!rootDir || !archivePath || !downloadUrl) {
    fail("Bundled git paths could not be resolved.");
  }

  await fsp.mkdir(rootDir, { recursive: true });
  await ensureGitArchive(target, archivePath, downloadUrl);
  let gitExecutable;
  if (target.portableGitAsset) {
    gitExecutable = await ensurePortableGitPrefix(target, rootDir, archivePath);
  } else {
    const micromambaPath = await ensureMicromamba(target, rootDir, archivePath);
    gitExecutable = await ensureGitPrefix(target, rootDir, micromambaPath);
  }
  if (printBin) {
    console.log(gitExecutable);
  } else {
    log(`Bundled git ready: ${gitExecutable}`);
  }
}

await main();

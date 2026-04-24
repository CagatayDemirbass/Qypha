import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

export const bundledPythonRelease = {
  tag: "20260325",
  pythonVersion: "3.11.15",
  assetUrlPrefix:
    "https://github.com/astral-sh/python-build-standalone/releases/download/20260325",
  targets: {
    "darwin-arm64": {
      key: "darwin-arm64",
      assetName: "cpython-3.11.15+20260325-aarch64-apple-darwin-install_only.tar.gz",
    },
    "darwin-x64": {
      key: "darwin-x64",
      assetName: "cpython-3.11.15+20260325-x86_64-apple-darwin-install_only.tar.gz",
    },
    "linux-arm64-gnu": {
      key: "linux-arm64-gnu",
      assetName: "cpython-3.11.15+20260325-aarch64-unknown-linux-gnu-install_only.tar.gz",
    },
    "linux-arm64-musl": {
      key: "linux-arm64-musl",
      assetName: "cpython-3.11.15+20260325-aarch64-unknown-linux-musl-install_only.tar.gz",
    },
    "linux-x64-gnu": {
      key: "linux-x64-gnu",
      assetName: "cpython-3.11.15+20260325-x86_64-unknown-linux-gnu-install_only.tar.gz",
    },
    "linux-x64-musl": {
      key: "linux-x64-musl",
      assetName: "cpython-3.11.15+20260325-x86_64-unknown-linux-musl-install_only.tar.gz",
    },
    "win32-arm64": {
      key: "win32-arm64",
      assetName: "cpython-3.11.15+20260325-aarch64-pc-windows-msvc-install_only.tar.gz",
    },
    "win32-x64": {
      key: "win32-x64",
      assetName: "cpython-3.11.15+20260325-x86_64-pc-windows-msvc-install_only.tar.gz",
    },
  },
};

function detectLinuxLibc() {
  const override = process.env.QYPHA_BUNDLED_PYTHON_LIBC?.trim().toLowerCase();
  if (override === "gnu" || override === "musl") {
    return override;
  }
  const report = process.report?.getReport?.();
  if (report?.header?.glibcVersionRuntime) {
    return "gnu";
  }
  if (fs.existsSync("/etc/alpine-release")) {
    return "musl";
  }
  if (Array.isArray(report?.sharedObjects)) {
    const hasMusl = report.sharedObjects.some(
      (entry) => typeof entry === "string" && entry.toLowerCase().includes("musl"),
    );
    if (hasMusl) {
      return "musl";
    }
  }
  return "gnu";
}

function normalizeTargetKey(platform = process.platform, arch = process.arch) {
  if (platform === "darwin") {
    if (arch === "arm64") {
      return "darwin-arm64";
    }
    if (arch === "x64") {
      return "darwin-x64";
    }
    return undefined;
  }
  if (platform === "linux") {
    const libc = detectLinuxLibc();
    if (arch === "arm64") {
      return `linux-arm64-${libc}`;
    }
    if (arch === "x64") {
      return `linux-x64-${libc}`;
    }
    return undefined;
  }
  if (platform === "win32") {
    if (arch === "arm64") {
      return "win32-arm64";
    }
    if (arch === "x64") {
      return "win32-x64";
    }
    return undefined;
  }
  return undefined;
}

export function resolveBundledPythonTarget(platform = process.platform, arch = process.arch) {
  const override = process.env.QYPHA_BUNDLED_PYTHON_TARGET?.trim();
  const key = override || normalizeTargetKey(platform, arch);
  if (!key) {
    return undefined;
  }
  const target = bundledPythonRelease.targets[key];
  if (!target) {
    return undefined;
  }
  return target;
}

export function resolveBundledPythonInstallDir(
  platform = process.platform,
  arch = process.arch,
) {
  const target = resolveBundledPythonTarget(platform, arch);
  if (!target) {
    return undefined;
  }
  return path.resolve(moduleDir, target.key);
}

export function resolveBundledPythonArchivePath(
  platform = process.platform,
  arch = process.arch,
) {
  const target = resolveBundledPythonTarget(platform, arch);
  if (!target) {
    return undefined;
  }
  return path.resolve(moduleDir, ".downloads", target.assetName);
}

export function resolveBundledPythonExecutable(
  platform = process.platform,
  arch = process.arch,
) {
  const installDir = resolveBundledPythonInstallDir(platform, arch);
  if (!installDir) {
    return undefined;
  }
  if (platform === "win32") {
    return path.resolve(installDir, "python", "python.exe");
  }
  return path.resolve(installDir, "python", "bin", "python3");
}

export function buildBundledPythonDownloadUrl(
  platform = process.platform,
  arch = process.arch,
) {
  const target = resolveBundledPythonTarget(platform, arch);
  if (!target) {
    return undefined;
  }
  return `${bundledPythonRelease.assetUrlPrefix}/${target.assetName}`;
}

export function buildBundledPythonChecksumUrl() {
  return `${bundledPythonRelease.assetUrlPrefix}/SHA256SUMS`;
}

export function isBundledPythonInstalled(
  platform = process.platform,
  arch = process.arch,
) {
  const executable = resolveBundledPythonExecutable(platform, arch);
  return !!executable && fs.existsSync(executable);
}

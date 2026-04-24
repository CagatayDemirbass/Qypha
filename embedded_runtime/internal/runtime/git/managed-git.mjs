import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

export const bundledGitRelease = {
  channelBaseUrl: "https://conda.anaconda.org/conda-forge",
  windowsReleaseBaseUrl: "https://github.com/git-for-windows/git/releases/download",
  windowsReleaseTag: "v2.49.0.windows.1",
  gitSpec: "git=2.49.0",
  micromambaVersion: "2.5.0-1",
  targets: {
    "darwin-arm64": {
      key: "darwin-arm64",
      condaSubdir: "osx-arm64",
      micromambaAsset: "micromamba-2.5.0-1.tar.bz2",
      micromambaSha256:
        "1fb6b0c237ac6fa07b3d33baa56c08f51316564cd5cfa536d5ff5ecf114efadb",
    },
    "darwin-x64": {
      key: "darwin-x64",
      condaSubdir: "osx-64",
      micromambaAsset: "micromamba-2.5.0-1.tar.bz2",
      micromambaSha256:
        "a3b4390290481d5ea22fe8014cb99c857117013beea05ad95fd9268239e04a26",
    },
    "linux-arm64": {
      key: "linux-arm64",
      condaSubdir: "linux-aarch64",
      micromambaAsset: "micromamba-2.5.0-1.tar.bz2",
      micromambaSha256:
        "cbe498d65b4173d68875634985cad1b7f2561d4bee58126d084899d3ba3d9cd8",
    },
    "linux-x64": {
      key: "linux-x64",
      condaSubdir: "linux-64",
      micromambaAsset: "micromamba-2.5.0-1.tar.bz2",
      micromambaSha256:
        "4ae6e5cdff233616c94d4bb69cf77a572d67b0b227073de12c3aa0ff23795ded",
    },
    "win32-x64": {
      key: "win32-x64",
      condaSubdir: "win-64",
      portableGitAsset: "MinGit-2.49.0-64-bit.zip",
      portableGitSha256:
        "971cdee7c0feaa1e41369c46da88d1000a24e79a6f50191c820100338fb7eca5",
    },
    "win32-arm64": {
      key: "win32-arm64",
      condaSubdir: "win-64",
      portableGitAsset: "MinGit-2.49.0-64-bit.zip",
      portableGitSha256:
        "971cdee7c0feaa1e41369c46da88d1000a24e79a6f50191c820100338fb7eca5",
      emulated: true,
    },
  },
};

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
    if (arch === "arm64") {
      return "linux-arm64";
    }
    if (arch === "x64") {
      return "linux-x64";
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

export function resolveBundledGitTarget(platform = process.platform, arch = process.arch) {
  const override = process.env.QYPHA_BUNDLED_GIT_TARGET?.trim();
  const key = override || normalizeTargetKey(platform, arch);
  if (!key) {
    return undefined;
  }
  return bundledGitRelease.targets[key];
}

export function resolveBundledGitRootDir(platform = process.platform, arch = process.arch) {
  const target = resolveBundledGitTarget(platform, arch);
  if (!target) {
    return undefined;
  }
  return path.resolve(moduleDir, target.key);
}

export function resolveBundledGitArchivePath(platform = process.platform, arch = process.arch) {
  const target = resolveBundledGitTarget(platform, arch);
  if (!target) {
    return undefined;
  }
  const archiveName = target.portableGitAsset || target.micromambaAsset;
  if (!archiveName) {
    return undefined;
  }
  return path.resolve(moduleDir, ".downloads", target.condaSubdir, archiveName);
}

export function buildBundledGitMicromambaUrl(platform = process.platform, arch = process.arch) {
  const target = resolveBundledGitTarget(platform, arch);
  if (!target) {
    return undefined;
  }
  if (target.portableGitAsset) {
    return `${bundledGitRelease.windowsReleaseBaseUrl}/${bundledGitRelease.windowsReleaseTag}/${target.portableGitAsset}`;
  }
  return `${bundledGitRelease.channelBaseUrl}/${target.condaSubdir}/${target.micromambaAsset}`;
}

export function resolveBundledGitMicromambaExecutable(
  platform = process.platform,
  arch = process.arch,
) {
  const rootDir = resolveBundledGitRootDir(platform, arch);
  if (!rootDir) {
    return undefined;
  }
  if (platform === "win32") {
    return path.resolve(rootDir, "micromamba", "Library", "bin", "micromamba.exe");
  }
  return path.resolve(rootDir, "micromamba", "bin", "micromamba");
}

export function resolveBundledGitPrefix(platform = process.platform, arch = process.arch) {
  const rootDir = resolveBundledGitRootDir(platform, arch);
  if (!rootDir) {
    return undefined;
  }
  return path.resolve(rootDir, "prefix");
}

export function resolveBundledGitExecutable(platform = process.platform, arch = process.arch) {
  const prefix = resolveBundledGitPrefix(platform, arch);
  if (!prefix) {
    return undefined;
  }
  if (platform === "win32") {
    return path.resolve(prefix, "mingw64", "bin", "git.exe");
  }
  return path.resolve(prefix, "bin", "git");
}

export function resolveBundledGitBinDir(platform = process.platform, arch = process.arch) {
  const prefix = resolveBundledGitPrefix(platform, arch);
  if (!prefix) {
    return undefined;
  }
  if (platform === "win32") {
    return path.resolve(prefix, "mingw64", "bin");
  }
  return path.resolve(prefix, "bin");
}

export function isBundledGitInstalled(platform = process.platform, arch = process.arch) {
  const executable = resolveBundledGitExecutable(platform, arch);
  return !!executable && fs.existsSync(executable);
}

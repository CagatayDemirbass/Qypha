import fs from "node:fs";
import path from "node:path";
import type { OpenClawConfig } from "../config/config.js";
import { buildWorkspaceSkillStatus, type SkillStatusEntry } from "./skills-status.js";
import { loadWorkspaceSkillEntries, type SkillEntry } from "./skills.js";

type VerifyWorkspaceSkillResult =
  | {
      ok: true;
      entry: SkillEntry;
      status: SkillStatusEntry;
    }
  | {
      ok: false;
      error: string;
    };

function resolveComparablePath(filePath: string): string {
  try {
    return fs.realpathSync(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

export function verifyWorkspaceSkill(params: {
  workspaceDir: string;
  skillName?: string;
  config?: OpenClawConfig;
  expectedBaseDir?: string;
  requiredBins?: string[];
}): VerifyWorkspaceSkillResult {
  const entries = loadWorkspaceSkillEntries(params.workspaceDir, {
    config: params.config,
  });
  const expectedBaseDir = params.expectedBaseDir
    ? resolveComparablePath(params.expectedBaseDir)
    : undefined;
  const entry = entries.find((item) => {
    if (params.skillName && item.skill.name === params.skillName) {
      return true;
    }
    if (expectedBaseDir) {
      return resolveComparablePath(item.skill.baseDir) === expectedBaseDir;
    }
    return false;
  });
  const skillLabel = params.skillName ?? expectedBaseDir ?? "skill";
  if (!entry) {
    return {
      ok: false,
      error: `Skill "${skillLabel}" is not visible after install.`,
    };
  }
  if (expectedBaseDir) {
    const actualBaseDir = resolveComparablePath(entry.skill.baseDir);
    if (actualBaseDir !== expectedBaseDir) {
      return {
        ok: false,
        error:
          `Skill "${entry.skill.name}" loaded from an unexpected location: ` +
          `${actualBaseDir} (expected ${expectedBaseDir}).`,
      };
    }
  }

  const report = buildWorkspaceSkillStatus(params.workspaceDir, {
    config: params.config,
    entries,
  });
  const status = report.skills.find((item) => item.name === params.skillName);
  const resolvedStatus =
    status ?? report.skills.find((item) => resolveComparablePath(item.baseDir) === expectedBaseDir);
  if (!resolvedStatus) {
    return {
      ok: false,
      error: `Skill "${entry.skill.name}" status could not be resolved after install.`,
    };
  }

  const requiredBins = Array.from(
    new Set((params.requiredBins ?? []).map((bin) => bin.trim()).filter(Boolean)),
  );
  if (requiredBins.length > 0) {
    const missingRequiredBins = requiredBins.filter((bin) =>
      resolvedStatus.missing.bins.includes(bin),
    );
    if (missingRequiredBins.length > 0) {
      return {
        ok: false,
        error:
          `Skill "${entry.skill.name}" install did not make required binaries available: ` +
          missingRequiredBins.join(", "),
      };
    }
  }

  return {
    ok: true,
    entry,
    status: resolvedStatus,
  };
}

export type { VerifyWorkspaceSkillResult };

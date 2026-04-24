import fs from "node:fs/promises";
import path from "node:path";
import { Type } from "@sinclair/typebox";
import { compileGlobPattern, matchesAnyGlobPattern } from "../glob-pattern.js";
import { resolveRequiredHomeDir, expandHomePrefix } from "../../infra/home-dir.js";
import { isNotFoundPathError, isPathInside } from "../../infra/path-guards.js";
import type { AnyAgentTool } from "./common.js";
import {
  ToolInputError,
  readNumberParam,
  readStringArrayParam,
  readStringParam,
  textResult,
} from "./common.js";

const DEFAULT_LS_LIMIT = 200;
const MAX_LS_LIMIT = 2_000;
const DEFAULT_FIND_LIMIT = 200;
const MAX_FIND_LIMIT = 5_000;
const DEFAULT_GREP_MATCH_LIMIT = 100;
const MAX_GREP_MATCH_LIMIT = 2_000;
const DEFAULT_GREP_MAX_FILE_BYTES = 512 * 1024;
const MAX_GREP_CONTEXT_LINES = 8;
const MAX_GREP_SCAN_FILES = 5_000;

const lsSchema = Type.Object({
  path: Type.Optional(
    Type.String({
      description: "Directory or file path to list. Relative paths resolve from the workspace root.",
    }),
  ),
  recursive: Type.Optional(
    Type.Boolean({
      description: "When true, recursively include nested directory contents.",
    }),
  ),
  all: Type.Optional(
    Type.Boolean({
      description: "When true, include dotfiles and dot-directories.",
    }),
  ),
  limit: Type.Optional(
    Type.Integer({
      minimum: 1,
      maximum: MAX_LS_LIMIT,
      description: `Maximum number of entries to return. Defaults to ${DEFAULT_LS_LIMIT}.`,
    }),
  ),
});

const findSchema = Type.Object({
  path: Type.Optional(
    Type.String({
      description:
        "Directory to search. Relative paths resolve from the workspace root. Defaults to the workspace root.",
    }),
  ),
  glob: Type.Optional(
    Type.String({
      description:
        "Glob-style pattern to match (for example *.ts, src/**/*.rs, or **/package.json).",
    }),
  ),
  pattern: Type.Optional(
    Type.String({
      description: "Alias for glob.",
    }),
  ),
  type: Type.Optional(
    Type.Union([
      Type.Literal("all"),
      Type.Literal("files"),
      Type.Literal("directories"),
    ]),
  ),
  all: Type.Optional(
    Type.Boolean({
      description: "When true, include dotfiles and dot-directories in the search.",
    }),
  ),
  limit: Type.Optional(
    Type.Integer({
      minimum: 1,
      maximum: MAX_FIND_LIMIT,
      description: `Maximum number of matches to return. Defaults to ${DEFAULT_FIND_LIMIT}.`,
    }),
  ),
});

const grepSchema = Type.Object({
  pattern: Type.String({
    description:
      "Regular-expression pattern to search for. If the regex is invalid, the pattern is treated as plain text.",
  }),
  path: Type.Optional(
    Type.String({
      description:
        "File or directory to search. Relative paths resolve from the workspace root. Defaults to the workspace root.",
    }),
  ),
  glob: Type.Optional(
    Type.Union([
      Type.String({
        description:
          "Optional glob that narrows which files are searched (for example *.ts or src/**/*.md).",
      }),
      Type.Array(Type.String(), {
        description: "Optional list of glob patterns used to include files in the search.",
      }),
    ]),
  ),
  caseSensitive: Type.Optional(
    Type.Boolean({
      description: "When true, perform a case-sensitive search.",
    }),
  ),
  context: Type.Optional(
    Type.Integer({
      minimum: 0,
      maximum: MAX_GREP_CONTEXT_LINES,
      description: "How many lines of context to include around each match.",
    }),
  ),
  maxMatches: Type.Optional(
    Type.Integer({
      minimum: 1,
      maximum: MAX_GREP_MATCH_LIMIT,
      description: `Maximum number of matches to return. Defaults to ${DEFAULT_GREP_MATCH_LIMIT}.`,
    }),
  ),
  all: Type.Optional(
    Type.Boolean({
      description: "When true, include dotfiles and dot-directories while walking directories.",
    }),
  ),
});

type ResolvedTarget = {
  root: string;
  absolutePath: string;
  relativePath: string;
  stat: Awaited<ReturnType<typeof fs.stat>>;
};

type WalkEntry = {
  absolutePath: string;
  relativePath: string;
  name: string;
  type: "file" | "directory" | "other";
  size: number;
  mtimeMs: number;
};

function normalizePathForMatch(value: string): string {
  const normalized = value.split(path.sep).join("/");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function sortEntries(a: WalkEntry, b: WalkEntry): number {
  if (a.type !== b.type) {
    if (a.type === "directory") {
      return -1;
    }
    if (b.type === "directory") {
      return 1;
    }
  }
  return a.relativePath.localeCompare(b.relativePath);
}

function readBooleanParam(params: Record<string, unknown>, key: string): boolean | undefined {
  const raw = params[key];
  if (typeof raw === "boolean") {
    return raw;
  }
  if (typeof raw === "string") {
    const normalized = raw.trim().toLowerCase();
    if (normalized === "true") {
      return true;
    }
    if (normalized === "false") {
      return false;
    }
  }
  return undefined;
}

function readStringFromAliases(
  params: Record<string, unknown>,
  aliases: string[],
): string | undefined {
  for (const alias of aliases) {
    const value = readStringParam(params, alias);
    if (value) {
      return value;
    }
  }
  return undefined;
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${bytes} B`;
}

function looksHidden(name: string): boolean {
  return name.startsWith(".");
}

function coerceStatNumber(value: number | bigint): number {
  return typeof value === "bigint" ? Number(value) : value;
}

function renderEntry(entry: WalkEntry): string {
  const suffix = entry.type === "directory" ? "/" : "";
  if (entry.type === "directory") {
    return `${entry.relativePath}${suffix}`;
  }
  return `${entry.relativePath}${suffix} (${formatSize(entry.size)})`;
}

async function resolveTargetPath(params: {
  workspaceRoot: string;
  requestedPath?: string;
}): Promise<ResolvedTarget> {
  const root = await fs.realpath(params.workspaceRoot).catch(() => path.resolve(params.workspaceRoot));
  const rawInput = params.requestedPath?.trim() || ".";
  const expanded = rawInput.startsWith("~")
    ? expandHomePrefix(rawInput, { home: resolveRequiredHomeDir() })
    : rawInput;
  const lexicalTarget = path.isAbsolute(expanded)
    ? path.resolve(expanded)
    : path.resolve(root, expanded);

  if (!isPathInside(root, lexicalTarget)) {
    throw new ToolInputError(`Path must stay within workspace root: ${root}`);
  }

  let lstat;
  try {
    lstat = await fs.lstat(lexicalTarget);
  } catch (error) {
    if (isNotFoundPathError(error)) {
      throw new ToolInputError(`Path not found: ${rawInput}`);
    }
    throw error;
  }

  if (lstat.isSymbolicLink()) {
    throw new ToolInputError(`Symlink paths are not supported: ${rawInput}`);
  }

  const absolutePath = await fs.realpath(lexicalTarget).catch(() => lexicalTarget);
  if (!isPathInside(root, absolutePath)) {
    throw new ToolInputError(`Resolved path escapes workspace root: ${rawInput}`);
  }

  const stat = await fs.stat(absolutePath);
  const relativeRaw = path.relative(root, absolutePath);
  const relativePath = relativeRaw ? normalizePathForMatch(relativeRaw) : ".";
  return { root, absolutePath, relativePath, stat };
}

async function collectWalkEntries(params: {
  root: string;
  start: ResolvedTarget;
  recursive: boolean;
  includeHidden: boolean;
  limit: number;
  includeDirectories?: boolean;
  includeFiles?: boolean;
}): Promise<{ entries: WalkEntry[]; truncated: boolean }> {
  const includeDirectories = params.includeDirectories !== false;
  const includeFiles = params.includeFiles !== false;
  const entries: WalkEntry[] = [];
  const queue: Array<{ absolutePath: string; relativePath: string }> = [];
  let truncated = false;

  const pushEntry = (entry: WalkEntry) => {
    if (entries.length >= params.limit) {
      truncated = true;
      return false;
    }
    entries.push(entry);
    return true;
  };

  if (params.start.stat.isDirectory()) {
    queue.push({ absolutePath: params.start.absolutePath, relativePath: params.start.relativePath });
  } else {
    if (includeFiles) {
      pushEntry({
        absolutePath: params.start.absolutePath,
        relativePath: params.start.relativePath,
        name: path.basename(params.start.absolutePath),
        type: "file",
        size: coerceStatNumber(params.start.stat.size),
        mtimeMs: coerceStatNumber(params.start.stat.mtimeMs),
      });
    }
    return { entries, truncated };
  }

  while (queue.length > 0 && !truncated) {
    const current = queue.shift()!;
    const dirEntries = await fs.readdir(current.absolutePath, { withFileTypes: true });
    dirEntries.sort((a, b) => a.name.localeCompare(b.name));

    for (const dirent of dirEntries) {
      if (!params.includeHidden && looksHidden(dirent.name)) {
        continue;
      }

      const absolutePath = path.join(current.absolutePath, dirent.name);
      let lstat;
      try {
        lstat = await fs.lstat(absolutePath);
      } catch {
        continue;
      }
      if (lstat.isSymbolicLink()) {
        continue;
      }

      const realPath = await fs.realpath(absolutePath).catch(() => absolutePath);
      if (!isPathInside(params.root, realPath)) {
        continue;
      }

      const relativePath = normalizePathForMatch(path.relative(params.root, realPath));
      const type: WalkEntry["type"] = lstat.isDirectory()
        ? "directory"
        : lstat.isFile()
          ? "file"
          : "other";

      if ((type === "directory" && includeDirectories) || (type === "file" && includeFiles)) {
        const keepGoing = pushEntry({
          absolutePath: realPath,
          relativePath,
          name: dirent.name,
          type,
          size: coerceStatNumber(lstat.size),
          mtimeMs: coerceStatNumber(lstat.mtimeMs),
        });
        if (!keepGoing) {
          break;
        }
      }

      if (params.recursive && type === "directory") {
        queue.push({ absolutePath: realPath, relativePath });
      }
    }
  }

  entries.sort(sortEntries);
  return { entries, truncated };
}

function compileMatchers(globs: string[]): ReturnType<typeof compileGlobPattern>[] {
  return globs
    .map((glob) =>
      compileGlobPattern({
        raw: glob,
        normalize: normalizePathForMatch,
      }),
    )
    .filter((matcher) => matcher.kind !== "exact" || matcher.value.length > 0);
}

function matchesGlob(params: {
  relativePath: string;
  basename: string;
  matchers: ReturnType<typeof compileGlobPattern>[];
}): boolean {
  if (params.matchers.length === 0) {
    return true;
  }
  const relativePath = normalizePathForMatch(params.relativePath);
  const basename = normalizePathForMatch(params.basename);
  return (
    matchesAnyGlobPattern(relativePath, params.matchers) ||
    matchesAnyGlobPattern(basename, params.matchers)
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function compileSearchRegex(pattern: string, caseSensitive: boolean): RegExp {
  const regexFlags = caseSensitive ? "m" : "im";
  try {
    return new RegExp(pattern, regexFlags);
  } catch {
    return new RegExp(escapeRegExp(pattern), regexFlags);
  }
}

function isProbablyBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 4096);
  return sample.includes(0);
}

function formatContextMatch(params: {
  relativePath: string;
  lineNumber: number;
  lineText: string;
  contextBefore: Array<{ lineNumber: number; text: string }>;
  contextAfter: Array<{ lineNumber: number; text: string }>;
}): string {
  const lines: string[] = [];
  for (const line of params.contextBefore) {
    lines.push(`${params.relativePath}-${line.lineNumber}- ${line.text}`);
  }
  lines.push(`${params.relativePath}:${params.lineNumber}: ${params.lineText}`);
  for (const line of params.contextAfter) {
    lines.push(`${params.relativePath}-${line.lineNumber}- ${line.text}`);
  }
  return lines.join("\n");
}

export function createLsTool(params: { workspaceDir: string }): AnyAgentTool {
  return {
    name: "ls",
    label: "ls",
    description:
      "List directory contents under the active workspace root. Use this to inspect files and folders without running a shell command. Supports recursive listings and hidden files.",
    parameters: lsSchema,
    execute: async (_toolCallId, rawArgs) => {
      const args = rawArgs as Record<string, unknown>;
      const target = await resolveTargetPath({
        workspaceRoot: params.workspaceDir,
        requestedPath: readStringFromAliases(args, ["path", "dir", "directory"]),
      });
      const recursive = readBooleanParam(args, "recursive") === true;
      const all = readBooleanParam(args, "all") === true;
      const limit = Math.min(
        MAX_LS_LIMIT,
        Math.max(1, readNumberParam(args, "limit", { integer: true }) ?? DEFAULT_LS_LIMIT),
      );

      if (target.stat.isFile()) {
        const entry: WalkEntry = {
          absolutePath: target.absolutePath,
          relativePath: target.relativePath,
          name: path.basename(target.absolutePath),
          type: "file",
          size: coerceStatNumber(target.stat.size),
          mtimeMs: coerceStatNumber(target.stat.mtimeMs),
        };
        return textResult(renderEntry(entry), {
          status: "completed",
          root: target.root,
          path: target.relativePath,
          entries: [entry],
          truncated: false,
        });
      }

      const { entries, truncated } = await collectWalkEntries({
        root: target.root,
        start: target,
        recursive,
        includeHidden: all,
        limit,
      });

      const lines =
        entries.length > 0
          ? entries.map((entry) => renderEntry(entry))
          : [`(empty) ${target.relativePath}`];
      if (truncated) {
        lines.push(`\n[truncated after ${limit} entries]`);
      }
      return textResult(lines.join("\n"), {
        status: "completed",
        root: target.root,
        path: target.relativePath,
        recursive,
        all,
        truncated,
        entries,
      });
    },
  };
}

export function createFindTool(params: { workspaceDir: string }): AnyAgentTool {
  return {
    name: "find",
    label: "find",
    description:
      "Find files or directories under the active workspace root using a glob-style pattern. Use this when you know roughly what path or filename you want but need exact matches.",
    parameters: findSchema,
    execute: async (_toolCallId, rawArgs) => {
      const args = rawArgs as Record<string, unknown>;
      const glob =
        readStringFromAliases(args, ["glob", "pattern", "name"]) ??
        (() => {
          throw new ToolInputError("glob required");
        })();
      const target = await resolveTargetPath({
        workspaceRoot: params.workspaceDir,
        requestedPath: readStringFromAliases(args, ["path", "dir", "directory"]),
      });
      const includeHidden = readBooleanParam(args, "all") === true;
      const limit = Math.min(
        MAX_FIND_LIMIT,
        Math.max(1, readNumberParam(args, "limit", { integer: true }) ?? DEFAULT_FIND_LIMIT),
      );
      const typeRaw = readStringParam(args, "type")?.toLowerCase();
      const type =
        typeRaw === "files" || typeRaw === "directories" || typeRaw === "all" ? typeRaw : "all";
      const matchers = compileMatchers([glob]);

      const { entries, truncated } = await collectWalkEntries({
        root: target.root,
        start: target,
        recursive: true,
        includeHidden,
        limit: Math.max(limit * 2, limit),
        includeDirectories: type !== "files",
        includeFiles: type !== "directories",
      });

      const matches = entries.filter((entry) =>
        matchesGlob({
          relativePath: entry.relativePath,
          basename: entry.name,
          matchers,
        }),
      );
      const limitedMatches = matches.slice(0, limit);
      const output =
        limitedMatches.length > 0 ? limitedMatches.map((entry) => renderEntry(entry)).join("\n") : "(no matches)";
      const wasTruncated = truncated || matches.length > limit;
      return textResult(wasTruncated ? `${output}\n\n[truncated after ${limit} matches]` : output, {
        status: "completed",
        root: target.root,
        path: target.relativePath,
        glob,
        type,
        truncated: wasTruncated,
        matches: limitedMatches,
      });
    },
  };
}

export function createGrepTool(params: { workspaceDir: string }): AnyAgentTool {
  return {
    name: "grep",
    label: "grep",
    description:
      "Search file contents under the active workspace root using a regular-expression pattern. Use this to find text across one file or a whole directory tree without dropping to exec.",
    parameters: grepSchema,
    execute: async (_toolCallId, rawArgs) => {
      const args = rawArgs as Record<string, unknown>;
      const pattern = readStringParam(args, "pattern", { required: true });
      const target = await resolveTargetPath({
        workspaceRoot: params.workspaceDir,
        requestedPath: readStringFromAliases(args, ["path", "dir", "directory"]),
      });
      const includeHidden = readBooleanParam(args, "all") === true;
      const caseSensitive = readBooleanParam(args, "caseSensitive") === true;
      const context = Math.min(
        MAX_GREP_CONTEXT_LINES,
        Math.max(0, readNumberParam(args, "context", { integer: true }) ?? 0),
      );
      const maxMatches = Math.min(
        MAX_GREP_MATCH_LIMIT,
        Math.max(
          1,
          readNumberParam(args, "maxMatches", { integer: true }) ?? DEFAULT_GREP_MATCH_LIMIT,
        ),
      );
      const globFilters = readStringArrayParam(args, "glob") ?? [];
      const matchers = compileMatchers(globFilters);
      const regex = compileSearchRegex(pattern, caseSensitive);

      const files: WalkEntry[] = [];
      if (target.stat.isFile()) {
        files.push({
          absolutePath: target.absolutePath,
          relativePath: target.relativePath,
          name: path.basename(target.absolutePath),
          type: "file",
          size: coerceStatNumber(target.stat.size),
          mtimeMs: coerceStatNumber(target.stat.mtimeMs),
        });
      } else {
        const walked = await collectWalkEntries({
          root: target.root,
          start: target,
          recursive: true,
          includeHidden,
          limit: MAX_GREP_SCAN_FILES,
          includeDirectories: false,
          includeFiles: true,
        });
        files.push(...walked.entries.filter((entry) => entry.type === "file"));
      }

      const outputBlocks: string[] = [];
      const detailsMatches: Array<{ path: string; line: number; text: string }> = [];
      const skipped: string[] = [];

      for (const file of files) {
        if (detailsMatches.length >= maxMatches) {
          break;
        }
        if (
          matchers.length > 0 &&
          !matchesGlob({
            relativePath: file.relativePath,
            basename: file.name,
            matchers,
          })
        ) {
          continue;
        }
        if (file.size > DEFAULT_GREP_MAX_FILE_BYTES) {
          skipped.push(`${file.relativePath} (skipped large file)`);
          continue;
        }

        let buffer: Buffer;
        try {
          buffer = await fs.readFile(file.absolutePath);
        } catch {
          skipped.push(`${file.relativePath} (read failed)`);
          continue;
        }

        if (isProbablyBinary(buffer)) {
          skipped.push(`${file.relativePath} (skipped binary file)`);
          continue;
        }

        const text = buffer.toString("utf8");
        const lines = text.split(/\r?\n/);
        for (let index = 0; index < lines.length; index += 1) {
          const lineText = lines[index] ?? "";
          if (!regex.test(lineText)) {
            continue;
          }
          const lineNumber = index + 1;
          const contextBefore =
            context > 0
              ? lines
                  .slice(Math.max(0, index - context), index)
                  .map((textLine, offset, source) => ({
                    lineNumber: lineNumber - source.length + offset,
                    text: textLine,
                  }))
              : [];
          const contextAfter =
            context > 0
              ? lines
                  .slice(index + 1, Math.min(lines.length, index + 1 + context))
                  .map((textLine, offset) => ({
                    lineNumber: lineNumber + offset + 1,
                    text: textLine,
                  }))
              : [];

          outputBlocks.push(
            formatContextMatch({
              relativePath: file.relativePath,
              lineNumber,
              lineText,
              contextBefore,
              contextAfter,
            }),
          );
          detailsMatches.push({
            path: file.relativePath,
            line: lineNumber,
            text: lineText,
          });
          if (detailsMatches.length >= maxMatches) {
            break;
          }
        }
      }

      let output =
        outputBlocks.length > 0 ? outputBlocks.join("\n\n") : "(no matches)";
      if (detailsMatches.length >= maxMatches) {
        output += `\n\n[truncated after ${maxMatches} matches]`;
      }
      if (skipped.length > 0) {
        output += `\n\nSkipped:\n${skipped.slice(0, 20).join("\n")}`;
        if (skipped.length > 20) {
          output += `\n... ${skipped.length - 20} more skipped files`;
        }
      }

      return textResult(output, {
        status: "completed",
        root: target.root,
        path: target.relativePath,
        pattern,
        caseSensitive,
        context,
        maxMatches,
        matches: detailsMatches,
        skipped,
      });
    },
  };
}

import { spawn } from "node:child_process";
import { once } from "node:events";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Type } from "@sinclair/typebox";
import { detectBinary } from "../../infra/detect-binary.js";
import { isPathInside, isNotFoundPathError } from "../../infra/path-guards.js";
import { execFileUtf8 } from "../../daemon/exec-file.js";
import { resolveUserPath } from "../../utils.js";
import type { AnyAgentTool, ToolFsPolicy } from "./tool-runtime.helpers.js";
import { normalizeWorkspaceDir } from "./tool-runtime.helpers.js";
import { ToolInputError, jsonResult } from "./common.js";

const DOCUMENT_FORMATS = ["pdf", "docx", "xlsx"] as const;
type DocumentFormat = (typeof DOCUMENT_FORMATS)[number];

const DocumentSectionSchema = Type.Object({
  heading: Type.Optional(Type.String()),
  text: Type.Optional(Type.String()),
  paragraphs: Type.Optional(Type.Array(Type.String())),
  bullets: Type.Optional(Type.Array(Type.String())),
});

const DocumentCellSchema = Type.Union([Type.String(), Type.Number(), Type.Boolean(), Type.Null()]);

const DocumentSheetChartSchema = Type.Object({
  type: Type.Optional(
    Type.Union([Type.Literal("column"), Type.Literal("bar")], {
      description:
        "Embedded Excel chart type. Use column for vertical bars or bar for horizontal bars. This tool writes the chart into the XLSX file itself.",
    }),
  ),
  title: Type.Optional(Type.String({ description: "Optional chart title." })),
  anchor: Type.Optional(
    Type.String({
      description: 'Cell anchor where the chart should be placed, for example "D2".',
    }),
  ),
  headerRow: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "1-based header row used for series titles. Omit to infer from the first row when present.",
    }),
  ),
  dataStartRow: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "1-based first data row for the chart series.",
    }),
  ),
  dataEndRow: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "1-based last data row for the chart series.",
    }),
  ),
  dataStartColumn: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "1-based first worksheet column to chart.",
    }),
  ),
  dataEndColumn: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "1-based last worksheet column to chart.",
    }),
  ),
  categoriesColumn: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "Optional 1-based worksheet column to use as chart categories.",
    }),
  ),
  categoriesStartRow: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "Optional first row for chart categories.",
    }),
  ),
  categoriesEndRow: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "Optional last row for chart categories.",
    }),
  ),
  seriesColors: Type.Optional(
    Type.Array(Type.String(), {
      description:
        'Optional per-series colors in worksheet order, for example ["0000FF", "FF0000"].',
    }),
  ),
  style: Type.Optional(
    Type.Integer({
      minimum: 1,
      description: "Optional Excel chart style preset number.",
    }),
  ),
  xAxisTitle: Type.Optional(Type.String({ description: "Optional X-axis title." })),
  yAxisTitle: Type.Optional(Type.String({ description: "Optional Y-axis title." })),
});

const DocumentSheetSchema = Type.Object({
  name: Type.String({ description: "Worksheet name." }),
  rows: Type.Array(Type.Array(DocumentCellSchema), {
    description: "Tabular worksheet rows.",
  }),
  charts: Type.Optional(
    Type.Array(DocumentSheetChartSchema, {
      description: "Optional embedded Excel charts for this worksheet.",
    }),
  ),
});

const DocumentGenerateToolSchema = Type.Object({
  format: Type.Union(
    DOCUMENT_FORMATS.map((value) => Type.Literal(value)) as [
      ReturnType<typeof Type.Literal>,
      ReturnType<typeof Type.Literal>,
      ReturnType<typeof Type.Literal>,
    ],
    {
      description: "Document format to generate: pdf, docx, or xlsx.",
    },
  ),
  path: Type.String({
    description:
      "Destination file path. Absolute paths are allowed when full host access is enabled; relative paths resolve from the workspace root.",
  }),
  title: Type.Optional(
    Type.String({
      description: "Optional document title.",
    }),
  ),
  content: Type.Optional(
    Type.String({
      description: "Optional main body content for pdf/docx generation.",
    }),
  ),
  sections: Type.Optional(
    Type.Array(DocumentSectionSchema, {
      description: "Optional structured sections for pdf/docx generation.",
    }),
  ),
  sheets: Type.Optional(
    Type.Array(DocumentSheetSchema, {
      description: "Worksheet definitions for xlsx generation.",
    }),
  ),
  overwrite: Type.Optional(
    Type.Boolean({
      description: "When true, replace an existing target file.",
    }),
  ),
});

type DocumentSection = {
  heading?: string;
  text?: string;
  paragraphs?: string[];
  bullets?: string[];
};

type DocumentSheet = {
  name: string;
  rows: Array<Array<string | number | boolean | null>>;
  charts?: Array<{
    type?: "column" | "bar";
    title?: string;
    anchor?: string;
    headerRow?: number;
    dataStartRow?: number;
    dataEndRow?: number;
    dataStartColumn?: number;
    dataEndColumn?: number;
    categoriesColumn?: number;
    categoriesStartRow?: number;
    categoriesEndRow?: number;
    seriesColors?: string[];
    style?: number;
    xAxisTitle?: string;
    yAxisTitle?: string;
  }>;
};

type DocumentGenerateSuccess = {
  ok: true;
  format: DocumentFormat;
  path: string;
  sizeBytes: number;
  title?: string;
};

type DocumentGenerateFailure = {
  ok: false;
  error: string;
  errorType?: "input" | "runtime" | "dependency";
};

type DocumentGenerateScriptResponse = DocumentGenerateSuccess | DocumentGenerateFailure;

let cachedPythonCommand: { command: string; prefixArgs: string[] } | null | undefined;
const pythonFormatSupportCache = new Map<string, boolean>();

function normalizeFormat(raw: unknown): DocumentFormat {
  if (typeof raw !== "string") {
    throw new ToolInputError("format required");
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === "pdf" || normalized === "docx" || normalized === "xlsx") {
    return normalized;
  }
  throw new ToolInputError("format must be one of pdf, docx, or xlsx");
}

function normalizeOptionalString(raw: unknown): string | undefined {
  if (typeof raw !== "string") {
    return undefined;
  }
  const trimmed = raw.trim();
  return trimmed || undefined;
}

function normalizeSections(raw: unknown): DocumentSection[] | undefined {
  if (!Array.isArray(raw)) {
    return undefined;
  }
  const sections: DocumentSection[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const record = entry as Record<string, unknown>;
    const heading = normalizeOptionalString(record.heading);
    const text = normalizeOptionalString(record.text);
    const paragraphs = Array.isArray(record.paragraphs)
      ? record.paragraphs
          .filter((value): value is string => typeof value === "string")
          .map((value) => value.trim())
          .filter(Boolean)
      : undefined;
    const bullets = Array.isArray(record.bullets)
      ? record.bullets
          .filter((value): value is string => typeof value === "string")
          .map((value) => value.trim())
          .filter(Boolean)
      : undefined;
    if (heading || text || (paragraphs?.length ?? 0) > 0 || (bullets?.length ?? 0) > 0) {
      sections.push({
        ...(heading ? { heading } : {}),
        ...(text ? { text } : {}),
        ...(paragraphs && paragraphs.length > 0 ? { paragraphs } : {}),
        ...(bullets && bullets.length > 0 ? { bullets } : {}),
      });
    }
  }
  return sections.length > 0 ? sections : undefined;
}

function normalizeSheets(raw: unknown): DocumentSheet[] | undefined {
  if (!Array.isArray(raw)) {
    return undefined;
  }
  const sheets: DocumentSheet[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const record = entry as Record<string, unknown>;
    const name = normalizeOptionalString(record.name);
    const rowsRaw = Array.isArray(record.rows) ? record.rows : [];
    const rows: DocumentSheet["rows"] = [];
    for (const row of rowsRaw) {
      if (!Array.isArray(row)) {
        continue;
      }
      rows.push(
        row.map((cell) => {
          if (
            typeof cell === "string" ||
            typeof cell === "number" ||
            typeof cell === "boolean" ||
            cell === null
          ) {
            return cell;
          }
          return String(cell);
        }),
      );
    }
    const chartsRaw = Array.isArray(record.charts) ? record.charts : [];
    const charts: NonNullable<DocumentSheet["charts"]> = [];
    for (const chartEntry of chartsRaw) {
      if (!chartEntry || typeof chartEntry !== "object") {
        continue;
      }
      const chartRecord = chartEntry as Record<string, unknown>;
      const typeRaw = normalizeOptionalString(chartRecord.type)
        ?.toLowerCase()
        .replace(/[-_]/g, " ");
      const type: "column" | "bar" | undefined =
        typeRaw === "bar" ||
        typeRaw === "bar chart" ||
        typeRaw === "bar plot" ||
        typeRaw === "horizontal bar" ||
        typeRaw === "horizontal bar chart"
          ? "bar"
          : typeRaw === "column" ||
              typeRaw === "col" ||
              typeRaw === "column chart" ||
              typeRaw === "column plot" ||
              typeRaw === "vertical bar" ||
              typeRaw === "vertical bar chart"
            ? "column"
            : undefined;
      const title = normalizeOptionalString(chartRecord.title);
      const anchor = normalizeOptionalString(chartRecord.anchor);
      const headerRow = readPositiveInteger(chartRecord.headerRow);
      const dataStartRow = readPositiveInteger(chartRecord.dataStartRow);
      const dataEndRow = readPositiveInteger(chartRecord.dataEndRow);
      const dataStartColumn = readPositiveInteger(chartRecord.dataStartColumn);
      const dataEndColumn = readPositiveInteger(chartRecord.dataEndColumn);
      const categoriesColumn = readPositiveInteger(chartRecord.categoriesColumn);
      const categoriesStartRow = readPositiveInteger(chartRecord.categoriesStartRow);
      const categoriesEndRow = readPositiveInteger(chartRecord.categoriesEndRow);
      const style = readPositiveInteger(chartRecord.style);
      const xAxisTitle = normalizeOptionalString(chartRecord.xAxisTitle);
      const yAxisTitle = normalizeOptionalString(chartRecord.yAxisTitle);
      const seriesColors = Array.isArray(chartRecord.seriesColors)
        ? chartRecord.seriesColors
            .filter((value): value is string => typeof value === "string")
            .map((value) => normalizeChartColor(value))
            .filter((value): value is string => Boolean(value))
        : undefined;
      charts.push({
        ...(type ? { type } : {}),
        ...(title ? { title } : {}),
        ...(anchor ? { anchor } : {}),
        ...(headerRow ? { headerRow } : {}),
        ...(dataStartRow ? { dataStartRow } : {}),
        ...(dataEndRow ? { dataEndRow } : {}),
        ...(dataStartColumn ? { dataStartColumn } : {}),
        ...(dataEndColumn ? { dataEndColumn } : {}),
        ...(categoriesColumn ? { categoriesColumn } : {}),
        ...(categoriesStartRow ? { categoriesStartRow } : {}),
        ...(categoriesEndRow ? { categoriesEndRow } : {}),
        ...(seriesColors && seriesColors.length > 0 ? { seriesColors } : {}),
        ...(style ? { style } : {}),
        ...(xAxisTitle ? { xAxisTitle } : {}),
        ...(yAxisTitle ? { yAxisTitle } : {}),
      });
    }
    if (name) {
      sheets.push({
        name,
        rows,
        ...(charts.length > 0 ? { charts } : {}),
      });
    }
  }
  return sheets.length > 0 ? sheets : undefined;
}

function readPositiveInteger(raw: unknown): number | undefined {
  if (typeof raw === "number" && Number.isInteger(raw) && raw >= 1) {
    return raw;
  }
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) {
      return undefined;
    }
    const parsed = Number.parseInt(trimmed, 10);
    if (Number.isInteger(parsed) && parsed >= 1) {
      return parsed;
    }
  }
  return undefined;
}

function normalizeChartColor(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/^#/, "").toUpperCase();
  return /^[0-9A-F]{6}$/.test(trimmed) ? trimmed : undefined;
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

function resolveDocumentScriptPath(): string {
  const candidates = [
    fileURLToPath(new URL("../../../scripts/document_generate.py", import.meta.url)),
    fileURLToPath(new URL("../scripts/document_generate.py", import.meta.url)),
  ].map((value) => path.resolve(value));
  for (const candidate of candidates) {
    if (fsSync.existsSync(candidate)) {
      return candidate;
    }
  }
  return candidates[0];
}

function resolveWorkspaceRoot(workspaceDir?: string): string {
  return normalizeWorkspaceDir(workspaceDir) ?? process.cwd();
}

async function resolveRealOrLexical(targetPath: string): Promise<string> {
  try {
    return await fs.realpath(targetPath);
  } catch (error) {
    if (isNotFoundPathError(error)) {
      return path.resolve(targetPath);
    }
    throw error;
  }
}

async function findExistingParent(targetPath: string): Promise<string> {
  let current = path.resolve(path.dirname(targetPath));
  while (true) {
    try {
      await fs.access(current);
      return current;
    } catch (error) {
      if (!isNotFoundPathError(error)) {
        throw error;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        return current;
      }
      current = parent;
    }
  }
}

async function resolveOutputPath(params: {
  requestedPath: string;
  format: DocumentFormat;
  workspaceDir?: string;
  fsPolicy?: ToolFsPolicy;
}): Promise<string> {
  const rawInput = params.requestedPath.trim();
  if (!rawInput) {
    throw new ToolInputError("path required");
  }
  const workspaceRoot = resolveWorkspaceRoot(params.workspaceDir);
  const workspaceRealRoot = await resolveRealOrLexical(workspaceRoot);
  const expanded = rawInput.startsWith("~") ? resolveUserPath(rawInput) : rawInput;
  const absolutePath = path.isAbsolute(expanded)
    ? path.resolve(expanded)
    : path.resolve(workspaceRoot, expanded);
  const ext = path.extname(absolutePath).toLowerCase();
  const expectedExt = `.${params.format}`;
  const normalizedPath = ext ? absolutePath : `${absolutePath}${expectedExt}`;
  if (path.extname(normalizedPath).toLowerCase() !== expectedExt) {
    throw new ToolInputError(`path extension must match format ${params.format}`);
  }
  const basename = path.basename(normalizedPath);
  if (!basename || basename === "." || basename === "..") {
    throw new ToolInputError("path must include a filename");
  }
  if (params.fsPolicy?.workspaceOnly) {
    if (!isPathInside(workspaceRealRoot, normalizedPath)) {
      throw new ToolInputError(`Path must stay within workspace root: ${workspaceRealRoot}`);
    }
    const existingParent = await findExistingParent(normalizedPath);
    const realExistingParent = await resolveRealOrLexical(existingParent);
    const relativeFromExisting = path.relative(existingParent, normalizedPath);
    const realTarget = path.resolve(realExistingParent, relativeFromExisting);
    if (!isPathInside(workspaceRealRoot, realTarget)) {
      throw new ToolInputError(`Resolved path escapes workspace root: ${rawInput}`);
    }
  }
  try {
    const stat = await fs.stat(normalizedPath);
    if (stat.isDirectory()) {
      throw new ToolInputError(`path points to a directory: ${normalizedPath}`);
    }
  } catch (error) {
    if (!isNotFoundPathError(error)) {
      throw error;
    }
  }
  return normalizedPath;
}

async function resolvePythonCommand(): Promise<{ command: string; prefixArgs: string[] }> {
  const candidates = [
    process.env.OPENCLAW_DOCUMENT_GENERATE_PYTHON?.trim(),
    process.env.QYPHA_DOCUMENT_GENERATE_PYTHON?.trim(),
    "python3",
    "python",
    process.platform === "win32" ? "py" : undefined,
    "/opt/homebrew/bin/python3",
    "/usr/local/bin/python3",
    "/usr/bin/python3",
  ].filter((value): value is string => Boolean(value));

  const resolvedCandidates: Array<{ command: string; prefixArgs: string[] }> = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const key = candidate.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (!(await detectBinary(candidate))) {
      continue;
    }
    resolvedCandidates.push(
      process.platform === "win32" && candidate.toLowerCase() === "py"
        ? { command: candidate, prefixArgs: ["-3"] }
        : { command: candidate, prefixArgs: [] },
    );
  }

  if (resolvedCandidates.length === 0) {
    cachedPythonCommand = null;
    throw new Error("Python 3 is required for document_generate but no interpreter was found.");
  }

  cachedPythonCommand = resolvedCandidates[0];
  return cachedPythonCommand;
}

function requiredImportForFormat(format: DocumentFormat): string {
  switch (format) {
    case "pdf":
      return "reportlab";
    case "docx":
      return "docx";
    case "xlsx":
      return "openpyxl";
  }
}

async function pythonSupportsFormat(
  interpreter: { command: string; prefixArgs: string[] },
  format: DocumentFormat,
): Promise<boolean> {
  const cacheKey = `${interpreter.command}\u0000${interpreter.prefixArgs.join("\u0001")}\u0000${format}`;
  const cached = pythonFormatSupportCache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }
  const result = await execFileUtf8(
    interpreter.command,
    [...interpreter.prefixArgs, "-c", `import ${requiredImportForFormat(format)}`],
    {},
  );
  const ok = result.code === 0;
  pythonFormatSupportCache.set(cacheKey, ok);
  return ok;
}

async function resolvePythonCommandForFormat(
  format: DocumentFormat,
): Promise<{ command: string; prefixArgs: string[] }> {
  const base = await resolvePythonCommand();
  if (await pythonSupportsFormat(base, format)) {
    return base;
  }

  const candidates = [
    process.env.OPENCLAW_DOCUMENT_GENERATE_PYTHON?.trim(),
    process.env.QYPHA_DOCUMENT_GENERATE_PYTHON?.trim(),
    "python3",
    "python",
    process.platform === "win32" ? "py" : undefined,
    "/opt/homebrew/bin/python3",
    "/usr/local/bin/python3",
    "/usr/bin/python3",
  ].filter((value): value is string => Boolean(value));

  const seen = new Set<string>();
  for (const candidate of candidates) {
    const normalized = candidate.toLowerCase();
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    if (!(await detectBinary(candidate))) {
      continue;
    }
    const interpreter =
      process.platform === "win32" && normalized === "py"
        ? { command: candidate, prefixArgs: ["-3"] }
        : { command: candidate, prefixArgs: [] };
    if (await pythonSupportsFormat(interpreter, format)) {
      cachedPythonCommand = interpreter;
      return interpreter;
    }
  }

  throw new Error(
    `Python environment for ${format.toUpperCase()} generation was found, but the required dependency "${requiredImportForFormat(format)}" is missing.`,
  );
}

async function runDocumentGenerateScript(
  spec: Record<string, unknown> & { format: DocumentFormat },
): Promise<DocumentGenerateScriptResponse> {
  const interpreter = await resolvePythonCommandForFormat(spec.format);
  const child = spawn(interpreter.command, [...interpreter.prefixArgs, resolveDocumentScriptPath()], {
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });

  const closePromise = once(child, "close") as Promise<[number | null, NodeJS.Signals | null]>;

  try {
    child.stdin.end(JSON.stringify(spec), "utf8");
    const [code, signal] = await closePromise;
    const parsed = stdout.trim() ? (JSON.parse(stdout) as DocumentGenerateScriptResponse) : null;
    if (parsed && typeof parsed === "object") {
      if (parsed.ok === true) {
        return parsed;
      }
      if (parsed.ok === false) {
        return parsed;
      }
    }
    const message =
      stderr.trim() ||
      `document_generate helper failed with code ${code ?? "null"} (${signal ?? "?"})`;
    return { ok: false, error: message, errorType: "runtime" };
  } catch (error) {
    child.kill("SIGKILL");
    await closePromise.catch(() => {});
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
      errorType: "runtime",
    };
  }
}

export function createDocumentGenerateTool(options?: {
  workspaceDir?: string;
  fsPolicy?: ToolFsPolicy;
}): AnyAgentTool {
  return {
    label: "Document Generate",
    name: "document_generate",
    description:
      "Generate real PDF, DOCX, or XLSX files. Use absolute paths for full host access, or relative paths to write from the workspace root. For pdf/docx provide content and/or sections. For xlsx provide sheets with row data and optional embedded charts. Excel bar/column charts are written directly into the workbook; do not tell the user to add them manually unless this tool call actually fails.",
    parameters: DocumentGenerateToolSchema,
    execute: async (_toolCallId, args) => {
      const record = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
      const format = normalizeFormat(record.format);
      if (typeof record.path !== "string") {
        throw new ToolInputError("path required");
      }
      const outputPath = await resolveOutputPath({
        requestedPath: record.path,
        format,
        workspaceDir: options?.workspaceDir,
        fsPolicy: options?.fsPolicy,
      });
      const title = normalizeOptionalString(record.title);
      const content = normalizeOptionalString(record.content);
      const sections = normalizeSections(record.sections);
      const sheets = normalizeSheets(record.sheets);
      const overwrite = record.overwrite === true;

      if ((format === "pdf" || format === "docx") && !content && !(sections && sections.length > 0)) {
        throw new ToolInputError(`${format} documents require content or sections`);
      }
      if (format === "xlsx" && !(sheets && sheets.length > 0)) {
        throw new ToolInputError("xlsx documents require sheets");
      }

      const result = await runDocumentGenerateScript({
        format,
        path: outputPath,
        ...(title ? { title } : {}),
        ...(content ? { content } : {}),
        ...(sections ? { sections } : {}),
        ...(sheets ? { sheets } : {}),
        overwrite,
      });

      if (!result.ok) {
        if (result.errorType === "input") {
          throw new ToolInputError(result.error);
        }
        throw new Error(result.error);
      }

      return jsonResult({
        status: "ok",
        format: result.format,
        path: result.path,
        sizeBytes: result.sizeBytes,
        size: formatSize(result.sizeBytes),
        ...(result.title ? { title: result.title } : {}),
        summary: `Generated ${result.format.toUpperCase()} document at ${result.path}`,
      });
    },
  };
}

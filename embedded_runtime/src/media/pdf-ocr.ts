import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { OEM, PSM, createWorker, type Worker } from "tesseract.js";

const OCR_LANGUAGE = "eng";
const OCR_LANG_DATA_DIR = "4.0.0_best_int";
const OCR_ENGINE = "tesseract.js";
const OCR_CACHE_DIR_NAME = "tesseract";
const MIN_OCR_TEXT_CHARS = 8;

let ocrWorkerPromise: Promise<Worker> | null = null;

type PdfOcrPageInput = {
  pageNumber: number;
  data: string;
  mimeType: string;
};

export type PdfOcrPageResult = {
  pageNumber: number;
  text: string;
  confidence: number | null;
};

export type PdfOcrResult = {
  engine: string;
  pages: PdfOcrPageResult[];
  text: string;
};

function normalizeOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function resolveOcrCacheRoot(): string {
  const explicitStateDir =
    normalizeOptionalString(process.env.QYPHA_RUNTIME_STATE_DIR) ??
    normalizeOptionalString(process.env.OPENCLAW_STATE_DIR);
  if (explicitStateDir) {
    return path.resolve(explicitStateDir, OCR_CACHE_DIR_NAME);
  }

  const explicitHomeDir =
    normalizeOptionalString(process.env.QYPHA_RUNTIME_HOME) ??
    normalizeOptionalString(process.env.OPENCLAW_HOME);
  if (explicitHomeDir) {
    return path.resolve(explicitHomeDir, ".qypha-runtime", OCR_CACHE_DIR_NAME);
  }

  return path.resolve(os.tmpdir(), "qypha-embedded-runtime", OCR_CACHE_DIR_NAME);
}

function ensureOcrCacheRoot(): string {
  const cacheRoot = resolveOcrCacheRoot();
  fs.mkdirSync(cacheRoot, { recursive: true });
  return cacheRoot;
}

function resolveBundledOcrLangPath(): string {
  const require = createRequire(import.meta.url);
  const pkgRoot = path.dirname(require.resolve("@tesseract.js-data/eng/package.json"));
  const langDir = path.resolve(pkgRoot, OCR_LANG_DATA_DIR);
  if (!fs.existsSync(path.resolve(langDir, `${OCR_LANGUAGE}.traineddata.gz`))) {
    throw new Error(`Bundled OCR language data not found in ${langDir}`);
  }
  return langDir;
}

async function getOcrWorker(): Promise<Worker> {
  if (!ocrWorkerPromise) {
    ocrWorkerPromise = (async () => {
      const worker = await createWorker(OCR_LANGUAGE, OEM.LSTM_ONLY, {
        langPath: resolveBundledOcrLangPath(),
        cachePath: ensureOcrCacheRoot(),
        gzip: true,
      });
      await worker.setParameters({
        preserve_interword_spaces: "1",
        tessedit_pageseg_mode: PSM.AUTO,
      });
      return worker;
    })().catch((error) => {
      ocrWorkerPromise = null;
      throw error;
    });
  }
  return await ocrWorkerPromise;
}

export async function recognizePdfPageImages(params: {
  pages: PdfOcrPageInput[];
  onPageError?: (pageNumber: number, error: unknown) => void;
}): Promise<PdfOcrResult> {
  if (params.pages.length === 0) {
    return { engine: OCR_ENGINE, pages: [], text: "" };
  }

  const worker = await getOcrWorker();
  const results: PdfOcrPageResult[] = [];

  for (const page of params.pages) {
    try {
      const buffer = Buffer.from(page.data, "base64");
      const recognized = await worker.recognize(buffer);
      const text = recognized.data.text.trim();
      if (text.length < MIN_OCR_TEXT_CHARS) {
        continue;
      }
      results.push({
        pageNumber: page.pageNumber,
        text,
        confidence:
          typeof recognized.data.confidence === "number" &&
          Number.isFinite(recognized.data.confidence)
            ? recognized.data.confidence
            : null,
      });
    } catch (error) {
      params.onPageError?.(page.pageNumber, error);
    }
  }

  const text = results
    .map((page) => `[ocr page ${page.pageNumber}]\n${page.text}`.trim())
    .join("\n\n")
    .trim();

  return {
    engine: OCR_ENGINE,
    pages: results,
    text,
  };
}

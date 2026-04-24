import path from "node:path";
import { createRequire } from "node:module";
import { recognizePdfPageImages } from "./pdf-ocr.js";

type CanvasModule = typeof import("@napi-rs/canvas");
type PdfJsModule = typeof import("pdfjs-dist/legacy/build/pdf.mjs");
type PdfDocumentInitParameters = Parameters<PdfJsModule["getDocument"]>[0];

const require = createRequire(import.meta.url);
let canvasModulePromise: Promise<CanvasModule> | null = null;
let pdfJsModulePromise: Promise<PdfJsModule> | null = null;
let pdfJsStandardFontDataUrl: string | null | undefined;

async function loadCanvasModule(): Promise<CanvasModule> {
  if (!canvasModulePromise) {
    canvasModulePromise = import("@napi-rs/canvas").catch((err) => {
      canvasModulePromise = null;
      throw new Error(
        `Optional dependency @napi-rs/canvas is required for PDF image extraction: ${String(err)}`,
      );
    });
  }
  return canvasModulePromise;
}

async function loadPdfJsModule(): Promise<PdfJsModule> {
  if (!pdfJsModulePromise) {
    pdfJsModulePromise = import("pdfjs-dist/legacy/build/pdf.mjs").catch((err) => {
      pdfJsModulePromise = null;
      throw new Error(
        `Optional dependency pdfjs-dist is required for PDF extraction: ${String(err)}`,
      );
    });
  }
  return pdfJsModulePromise;
}

function resolvePdfJsStandardFontDataUrl(): string | undefined {
  if (pdfJsStandardFontDataUrl !== undefined) {
    return pdfJsStandardFontDataUrl ?? undefined;
  }
  try {
    const packageJsonPath = require.resolve("pdfjs-dist/package.json");
    const standardFontsDir = path.join(path.dirname(packageJsonPath), "standard_fonts");
    pdfJsStandardFontDataUrl = `${standardFontsDir}${path.sep}`;
    return pdfJsStandardFontDataUrl;
  } catch {
    pdfJsStandardFontDataUrl = null;
    return undefined;
  }
}

export type PdfExtractedImage = {
  type: "image";
  data: string;
  mimeType: string;
  pageNumber?: number;
};

export type PdfExtractedOcr = {
  attempted?: boolean;
  applied: boolean;
  engine?: string;
  pages?: number[];
};

export type PdfExtractedContent = {
  text: string;
  images: PdfExtractedImage[];
  ocr?: PdfExtractedOcr;
};

export async function extractPdfContent(params: {
  buffer: Buffer;
  maxPages: number;
  maxPixels: number;
  minTextChars: number;
  pageNumbers?: number[];
  onImageExtractionError?: (error: unknown) => void;
  onOcrError?: (error: unknown) => void;
}): Promise<PdfExtractedContent> {
  const {
    buffer,
    maxPages,
    maxPixels,
    minTextChars,
    pageNumbers,
    onImageExtractionError,
    onOcrError,
  } = params;
  const { getDocument } = await loadPdfJsModule();
  const pdf = await getDocument({
    data: new Uint8Array(buffer),
    // pdf.js accepts this in Node runtimes, but the published union type omits it.
    disableWorker: true,
    standardFontDataUrl: resolvePdfJsStandardFontDataUrl(),
  } as unknown as PdfDocumentInitParameters).promise;

  const effectivePages: number[] = pageNumbers
    ? pageNumbers.filter((p) => p >= 1 && p <= pdf.numPages).slice(0, maxPages)
    : Array.from({ length: Math.min(pdf.numPages, maxPages) }, (_, i) => i + 1);

  const pageTextMap = new Map<number, string>();
  for (const pageNum of effectivePages) {
    const page = await pdf.getPage(pageNum);
    const textContent = await page.getTextContent();
    const pageText = textContent.items
      .map((item) => ("str" in item ? String(item.str) : ""))
      .filter(Boolean)
      .join(" ")
      .trim();
    if (pageText) {
      pageTextMap.set(pageNum, pageText);
    }
  }

  const text = effectivePages
    .map((pageNum) => pageTextMap.get(pageNum) ?? "")
    .filter((entry) => entry.trim().length > 0)
    .join("\n\n");
  if (text.trim().length >= minTextChars) {
    return { text, images: [], ocr: { attempted: false, applied: false } };
  }

  let canvasModule: CanvasModule;
  try {
    canvasModule = await loadCanvasModule();
  } catch (err) {
    onImageExtractionError?.(err);
    return { text, images: [], ocr: { attempted: false, applied: false } };
  }

  const { createCanvas } = canvasModule;
  const images: PdfExtractedImage[] = [];
  const pixelBudget = Math.max(1, maxPixels);

  for (const pageNum of effectivePages) {
    const page = await pdf.getPage(pageNum);
    const viewport = page.getViewport({ scale: 1 });
    const pagePixels = viewport.width * viewport.height;
    const scale = Math.min(1, Math.sqrt(pixelBudget / Math.max(1, pagePixels)));
    const scaled = page.getViewport({ scale: Math.max(0.1, scale) });
    const canvas = createCanvas(Math.ceil(scaled.width), Math.ceil(scaled.height));
    await page.render({
      canvas: canvas as unknown as HTMLCanvasElement,
      viewport: scaled,
    }).promise;
    const png = canvas.toBuffer("image/png");
    images.push({
      type: "image",
      data: png.toString("base64"),
      mimeType: "image/png",
      pageNumber: pageNum,
    });
  }

  const ocrCandidatePages = images.filter(
    (image) => ((pageTextMap.get(image.pageNumber ?? -1) ?? "").trim().length < 40),
  );

  if (ocrCandidatePages.length === 0) {
    return { text, images, ocr: { attempted: false, applied: false } };
  }

  try {
    const ocr = await recognizePdfPageImages({
      pages: ocrCandidatePages.map((page) => ({
        pageNumber: page.pageNumber ?? 0,
        data: page.data,
        mimeType: page.mimeType,
      })),
    });

    if (ocr.pages.length === 0) {
      return {
        text,
        images,
        ocr: { attempted: true, applied: false, engine: ocr.engine },
      };
    }

    const ocrPageTextMap = new Map(ocr.pages.map((page) => [page.pageNumber, page.text]));
    const mergedText = effectivePages
      .map((pageNum) => {
        const extractedText = (pageTextMap.get(pageNum) ?? "").trim();
        if (extractedText.length > 0) {
          return extractedText;
        }
        return (ocrPageTextMap.get(pageNum) ?? "").trim();
      })
      .filter((entry) => entry.length > 0)
      .join("\n\n");

    return {
      text: mergedText || text,
      images,
      ocr: {
        attempted: true,
        applied: true,
        engine: ocr.engine,
        pages: ocr.pages.map((page) => page.pageNumber),
      },
    };
  } catch (error) {
    onOcrError?.(error);
    return { text, images, ocr: { attempted: true, applied: false } };
  }
}

import { describe, expect, it } from "vitest";

import { allowClipboardCopy, isGhostMode } from "./privacy";

describe("ghost privacy policy", () => {
  it("detects ghost mode reliably", () => {
    expect(isGhostMode("ghost")).toBe(true);
    expect(isGhostMode(" GHOST ")).toBe(true);
    expect(isGhostMode("safe")).toBe(false);
    expect(isGhostMode("")).toBe(false);
  });

  it("blocks clipboard copy in ghost mode", () => {
    expect(allowClipboardCopy("ghost")).toBe(false);
    expect(allowClipboardCopy("safe")).toBe(true);
  });
});

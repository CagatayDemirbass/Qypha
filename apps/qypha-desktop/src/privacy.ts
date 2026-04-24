export function isGhostMode(mode: string | null | undefined): boolean {
  return String(mode || "").trim().toLowerCase() === "ghost";
}

export function allowClipboardCopy(mode: string | null | undefined): boolean {
  return !isGhostMode(mode);
}

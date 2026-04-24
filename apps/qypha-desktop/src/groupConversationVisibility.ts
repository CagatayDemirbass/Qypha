export interface GroupConversationActivityLike {
  kind?: string | null;
  tsMs?: number | null;
}

function normalizeTimestamp(value: number | null | undefined): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export function isGroupConversationRemovalKind(kind: string | null | undefined): boolean {
  const normalized = String(kind || "").trim().toLowerCase();
  return normalized === "group_removed" || normalized === "group_disbanded";
}

export function latestGroupConversationActivityTsMs<T extends GroupConversationActivityLike>(
  activities: T[]
): number {
  let latest = 0;
  for (const activity of activities) {
    if (isGroupConversationRemovalKind(activity.kind)) continue;
    const tsMs = normalizeTimestamp(activity.tsMs);
    if (tsMs > latest) {
      latest = tsMs;
    }
  }
  return latest;
}

export function shouldHideDeletedGroupConversation(args: {
  deletedAtMs?: number | null;
  groupStillPresent: boolean;
  latestActivityTsMs?: number | null;
}): boolean {
  const deletedAtMs = normalizeTimestamp(args.deletedAtMs);
  if (deletedAtMs <= 0) return false;
  if (!args.groupStillPresent) return true;
  return normalizeTimestamp(args.latestActivityTsMs) <= deletedAtMs;
}

export function isGroupConversationActivityVisibleAfterDelete(args: {
  deletedAtMs?: number | null;
  activityTsMs?: number | null;
}): boolean {
  const deletedAtMs = normalizeTimestamp(args.deletedAtMs);
  if (deletedAtMs <= 0) return true;
  return normalizeTimestamp(args.activityTsMs) > deletedAtMs;
}

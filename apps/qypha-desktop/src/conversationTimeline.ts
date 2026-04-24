export interface DirectMessageTimelineEventLike {
  ts_ms?: number | null;
}

export interface TransferTimelineEventLike {
  ts_ms?: number | null;
  group_id?: string | null;
}

export type DirectConversationTimelineEntry<TDirect, TTransfer> =
  | {
      kind: "direct";
      directEvent: TDirect;
      sortMs: number;
      sourceOrder: number;
    }
  | {
      kind: "transfer";
      transferEvent: TTransfer;
      sortMs: number;
      sourceOrder: number;
    };

export function buildDirectConversationTimeline<
  TDirect extends DirectMessageTimelineEventLike,
  TTransfer extends TransferTimelineEventLike
>(
  directEvents: TDirect[],
  transferEvents: TTransfer[]
): Array<DirectConversationTimelineEntry<TDirect, TTransfer>> {
  const timeline: Array<DirectConversationTimelineEntry<TDirect, TTransfer>> = [];
  let sourceOrder = 0;

  for (const event of directEvents) {
    timeline.push({
      kind: "direct",
      directEvent: event,
      sortMs: event.ts_ms || 0,
      sourceOrder: sourceOrder++
    });
  }

  for (const event of transferEvents) {
    if (String(event.group_id || "").trim()) continue;
    timeline.push({
      kind: "transfer",
      transferEvent: event,
      sortMs: event.ts_ms || 0,
      sourceOrder: sourceOrder++
    });
  }

  return timeline.sort((a, b) => {
    if (a.sortMs !== b.sortMs) return a.sortMs - b.sortMs;
    return a.sourceOrder - b.sourceOrder;
  });
}

export interface GroupEventTimelineLike {
  group_id: string;
  ts_ms?: number | null;
}

export interface GroupTransferTimelineLike {
  group_id?: string | null;
  ts_ms?: number | null;
}

export interface LocalGroupOutgoingTimelineLike {
  groupId: string;
  tsMs: number;
}

export type GroupConversationTimelineEntry<TGroupEvent, TTransferEvent, TLocalOutgoing> =
  | {
      kind: "group_event";
      groupEvent: TGroupEvent;
      sortMs: number;
      sourceOrder: number;
    }
  | {
      kind: "transfer_event";
      transferEvent: TTransferEvent;
      sortMs: number;
      sourceOrder: number;
    }
  | {
      kind: "local_outgoing";
      localOutgoing: TLocalOutgoing;
      sortMs: number;
      sourceOrder: number;
    };

export function buildGroupConversationTimeline<
  TGroupEvent extends GroupEventTimelineLike,
  TTransferEvent extends GroupTransferTimelineLike,
  TLocalOutgoing extends LocalGroupOutgoingTimelineLike
>(
  groupEvents: TGroupEvent[],
  transferEvents: TTransferEvent[],
  localOutgoing: TLocalOutgoing[]
): Array<GroupConversationTimelineEntry<TGroupEvent, TTransferEvent, TLocalOutgoing>> {
  const timeline: Array<GroupConversationTimelineEntry<TGroupEvent, TTransferEvent, TLocalOutgoing>> = [];
  let sourceOrder = 0;

  for (const event of groupEvents) {
    timeline.push({
      kind: "group_event",
      groupEvent: event,
      sortMs: event.ts_ms || 0,
      sourceOrder: sourceOrder++
    });
  }

  for (const event of transferEvents) {
    if (!String(event.group_id || "").trim()) continue;
    timeline.push({
      kind: "transfer_event",
      transferEvent: event,
      sortMs: event.ts_ms || 0,
      sourceOrder: sourceOrder++
    });
  }

  for (const entry of localOutgoing) {
    timeline.push({
      kind: "local_outgoing",
      localOutgoing: entry,
      sortMs: entry.tsMs || 0,
      sourceOrder: sourceOrder++
    });
  }

  return timeline.sort((a, b) => {
    if (a.sortMs !== b.sortMs) return a.sortMs - b.sortMs;
    return a.sourceOrder - b.sourceOrder;
  });
}

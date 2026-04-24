import { describe, expect, it } from "vitest";

import {
  conversationActivityTimestamp,
  defaultConversationKey,
  sortConversationsByActivity
} from "./conversationOrdering";

describe("conversation ordering", () => {
  it("sorts conversations by latest message timestamp regardless of type", () => {
    const ordered = sortConversationsByActivity([
      {
        key: "dm:agent1",
        type: "dm" as const,
        title: "Agent 1",
        messages: [{ seq: 1, tsMs: 100 }]
      },
      {
        key: "group:grp_1",
        type: "group" as const,
        title: "Team Group",
        messages: [{ seq: 2, tsMs: 250 }]
      }
    ]);

    expect(ordered.map((conversation) => conversation.key)).toEqual([
      "group:grp_1",
      "dm:agent1"
    ]);
  });

  it("falls back to sequence when timestamps are missing", () => {
    const ordered = sortConversationsByActivity([
      {
        key: "dm:older",
        type: "dm" as const,
        title: "Older",
        messages: [{ seq: 2 }]
      },
      {
        key: "dm:newer",
        type: "dm" as const,
        title: "Newer",
        messages: [{ seq: 5 }]
      }
    ]);

    expect(ordered[0]?.key).toBe("dm:newer");
  });

  it("returns latest conversation key for fallback selection", () => {
    const conversations = [
      {
        key: "dm:agent1",
        type: "dm" as const,
        title: "Agent 1",
        messages: [{ seq: 1, tsMs: 100 }]
      },
      {
        key: "group:grp_1",
        type: "group" as const,
        title: "Team Group",
        messages: [{ seq: 2, tsMs: 250 }]
      }
    ];

    expect(defaultConversationKey(conversations)).toBe("group:grp_1");
    expect(conversationActivityTimestamp(conversations[1])).toBe(250);
  });
});

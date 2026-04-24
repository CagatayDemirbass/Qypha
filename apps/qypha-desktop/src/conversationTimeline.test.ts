import { describe, expect, it } from "vitest";

import { buildDirectConversationTimeline } from "./conversationTimeline";

describe("conversation timeline", () => {
  it("keeps DM transfer events in chronological order with direct messages", () => {
    const timeline = buildDirectConversationTimeline(
      [
        { ts_ms: 100, id: "chat-1" },
        { ts_ms: 300, id: "chat-2" }
      ],
      [
        { ts_ms: 200, id: "transfer-1", group_id: null }
      ]
    );

    expect(
      timeline.map((entry) =>
        entry.kind === "direct" ? entry.directEvent.id : entry.transferEvent.id
      )
    ).toEqual(["chat-1", "transfer-1", "chat-2"]);
  });

  it("ignores group transfer events in DM timeline merge", () => {
    const timeline = buildDirectConversationTimeline(
      [{ ts_ms: 100, id: "chat-1" }],
      [
        { ts_ms: 90, id: "group-transfer", group_id: "grp_test" },
        { ts_ms: 110, id: "dm-transfer", group_id: null }
      ]
    );

    expect(
      timeline.map((entry) =>
        entry.kind === "direct" ? entry.directEvent.id : entry.transferEvent.id
      )
    ).toEqual(["chat-1", "dm-transfer"]);
  });
});

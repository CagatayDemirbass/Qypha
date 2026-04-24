import { describe, expect, it } from "vitest";

import { buildGroupConversationTimeline } from "./groupConversationTimeline";

describe("group conversation timeline", () => {
  it("merges group chat, group transfer, and local outgoing items chronologically", () => {
    const timeline = buildGroupConversationTimeline(
      [
        { group_id: "grp_1", ts_ms: 100, label: "chat-1" },
        { group_id: "grp_1", ts_ms: 300, label: "chat-2" }
      ],
      [
        { group_id: "grp_1", ts_ms: 200, label: "transfer-complete" }
      ],
      [
        { groupId: "grp_1", tsMs: 250, label: "local-outgoing" }
      ]
    );

    expect(
      timeline.map((entry) => {
        if (entry.kind === "group_event") return entry.groupEvent.label;
        if (entry.kind === "transfer_event") return entry.transferEvent.label;
        return entry.localOutgoing.label;
      })
    ).toEqual(["chat-1", "transfer-complete", "local-outgoing", "chat-2"]);
  });

  it("ignores non-group transfer events", () => {
    const timeline = buildGroupConversationTimeline(
      [{ group_id: "grp_1", ts_ms: 100, label: "chat-1" }],
      [{ group_id: "", ts_ms: 200, label: "dm-transfer" }],
      []
    );

    expect(timeline).toHaveLength(1);
    expect(timeline[0]?.kind).toBe("group_event");
  });
});

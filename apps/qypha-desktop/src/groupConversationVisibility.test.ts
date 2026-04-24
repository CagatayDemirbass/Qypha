import { describe, expect, it } from "vitest";

import {
  isGroupConversationActivityVisibleAfterDelete,
  latestGroupConversationActivityTsMs,
  shouldHideDeletedGroupConversation
} from "./groupConversationVisibility";

describe("group conversation visibility", () => {
  it("ignores removal-only events when checking for new activity", () => {
    const latest = latestGroupConversationActivityTsMs([
      { kind: "group_removed", tsMs: 400 },
      { kind: "group_disbanded", tsMs: 500 },
      { kind: "chat", tsMs: 250 }
    ]);

    expect(latest).toBe(250);
  });

  it("keeps a locally deleted group hidden when only stale history exists", () => {
    expect(
      shouldHideDeletedGroupConversation({
        deletedAtMs: 1000,
        groupStillPresent: true,
        latestActivityTsMs: 1000
      })
    ).toBe(true);
  });

  it("reopens a locally deleted group after fresh activity", () => {
    expect(
      shouldHideDeletedGroupConversation({
        deletedAtMs: 1000,
        groupStillPresent: true,
        latestActivityTsMs: 1250
      })
    ).toBe(false);
    expect(
      isGroupConversationActivityVisibleAfterDelete({
        deletedAtMs: 1000,
        activityTsMs: 1250
      })
    ).toBe(true);
    expect(
      isGroupConversationActivityVisibleAfterDelete({
        deletedAtMs: 1000,
        activityTsMs: 900
      })
    ).toBe(false);
  });

  it("keeps the group hidden once membership is gone", () => {
    expect(
      shouldHideDeletedGroupConversation({
        deletedAtMs: 1000,
        groupStillPresent: false,
        latestActivityTsMs: 5000
      })
    ).toBe(true);
  });
});

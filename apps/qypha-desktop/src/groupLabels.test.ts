import { describe, expect, it } from "vitest";

import { resolveMailboxGroupConversationLabel } from "./groupLabels";

describe("resolveMailboxGroupConversationLabel", () => {
  it("prefers the explicit event group name when present", () => {
    expect(
      resolveMailboxGroupConversationLabel(
        "grp_test",
        "g1",
        { group_id: "grp_test", group_name: "older-name" }
      )
    ).toBe("g1");
  });

  it("falls back to the mailbox group snapshot name", () => {
    expect(
      resolveMailboxGroupConversationLabel(
        "grp_test",
        null,
        { group_id: "grp_test", group_name: "g1" }
      )
    ).toBe("g1");
  });

  it("falls back to the group id when the snapshot is missing", () => {
    expect(resolveMailboxGroupConversationLabel("grp_test", null, null)).toBe("grp_test");
  });

  it("uses the generic label only when no name or id exists", () => {
    expect(resolveMailboxGroupConversationLabel(null, "   ", null)).toBe("Mailbox Group");
  });
});

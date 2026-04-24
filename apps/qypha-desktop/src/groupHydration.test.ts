import { describe, expect, it, vi } from "vitest";

import {
  hydrateMissingMailboxGroupSnapshot,
  snapshotContainsMailboxGroup
} from "./groupHydration";

describe("snapshotContainsMailboxGroup", () => {
  it("returns true when the target group exists in the runtime snapshot", () => {
    expect(
      snapshotContainsMailboxGroup(
        {
          runtime: {
            mailbox_groups: [{ group_id: "grp_1" }, { group_id: "grp_2" }]
          }
        },
        "grp_2"
      )
    ).toBe(true);
  });

  it("returns false when the runtime snapshot does not include the target group", () => {
    expect(
      snapshotContainsMailboxGroup(
        {
          runtime: {
            mailbox_groups: [{ group_id: "grp_1" }]
          }
        },
        "grp_2"
      )
    ).toBe(false);
  });
});

describe("hydrateMissingMailboxGroupSnapshot", () => {
  it("keeps the non-blocking result when it already contains the target group", async () => {
    const optimistic = {
      runtime: {
        mailbox_groups: [{ group_id: "grp_1" }]
      }
    };
    const tryLoad = vi.fn().mockResolvedValue(optimistic);
    const forceLoad = vi.fn().mockResolvedValue({
      runtime: {
        mailbox_groups: [{ group_id: "grp_1" }]
      }
    });

    await expect(
      hydrateMissingMailboxGroupSnapshot("grp_1", tryLoad, forceLoad)
    ).resolves.toEqual(optimistic);

    expect(tryLoad).toHaveBeenCalledTimes(1);
    expect(forceLoad).not.toHaveBeenCalled();
  });

  it("falls back to the guaranteed refresh when the optimistic snapshot is still missing the group", async () => {
    const tryLoad = vi.fn().mockResolvedValue({
      runtime: {
        mailbox_groups: []
      }
    });
    const forced = {
      runtime: {
        mailbox_groups: [{ group_id: "grp_1" }]
      }
    };
    const forceLoad = vi.fn().mockResolvedValue(forced);

    await expect(
      hydrateMissingMailboxGroupSnapshot("grp_1", tryLoad, forceLoad)
    ).resolves.toEqual(forced);

    expect(tryLoad).toHaveBeenCalledTimes(1);
    expect(forceLoad).toHaveBeenCalledTimes(1);
  });
});

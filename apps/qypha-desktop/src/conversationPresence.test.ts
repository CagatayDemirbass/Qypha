import { describe, expect, it } from "vitest";

import {
  shouldKeepImplicitDmConversation,
  shouldRenderConversationInList
} from "./conversationPresence";

describe("conversation presence", () => {
  it("renders runtime-listed peers without requiring messages", () => {
    expect(
      shouldRenderConversationInList({
        type: "dm",
        did: "did:nxf:peer1",
        messages: [],
        isPeerListed: true
      })
    ).toBe(true);
  });

  it("hides empty implicit DMs that are neither listed nor explicit", () => {
    expect(
      shouldRenderConversationInList({
        type: "dm",
        did: "did:nxf:peer1",
        messages: []
      })
    ).toBe(false);
    expect(
      shouldKeepImplicitDmConversation(
        {
          type: "dm",
          did: "did:nxf:peer1",
          messages: []
        },
        false
      )
    ).toBe(false);
  });

  it("keeps the active empty DM alive during local UI transitions", () => {
    expect(
      shouldKeepImplicitDmConversation(
        {
          type: "dm",
          did: "did:nxf:peer1",
          messages: []
        },
        true
      )
    ).toBe(true);
  });
});

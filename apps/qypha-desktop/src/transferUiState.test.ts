import { describe, expect, it } from "vitest";

import {
  applyTransferEventToTransferContext,
  reconcileTransferContextForPeer,
  resetTransferContextState,
  type TransferContextState
} from "./transferUiState";

function sampleContext(): TransferContextState {
  return {
    outgoingDid: "did:nxf:peer",
    outgoingSession: null,
    lastPackedDid: "did:nxf:peer",
    sessionDid: Object.create(null),
    localStage: "packing"
  };
}

describe("transfer UI state", () => {
  it("advances preparing state when outgoing events arrive", () => {
    const ctx = sampleContext();

    applyTransferEventToTransferContext(ctx, {
      direction: "outgoing",
      event: "outgoing_preparing",
      peer_did: "did:nxf:peer"
    });
    expect(ctx.localStage).toBe("preparing");

    applyTransferEventToTransferContext(ctx, {
      direction: "outgoing",
      event: "outgoing_pending",
      peer_did: "did:nxf:peer",
      session_id: "sess-1"
    });
    expect(ctx.localStage).toBe("pending");
    expect(ctx.outgoingSession).toBe("sess-1");

    applyTransferEventToTransferContext(ctx, {
      direction: "outgoing",
      event: "outgoing_accepted",
      peer_did: "did:nxf:peer",
      session_id: "sess-1"
    });
    expect(ctx.localStage).toBe("approved");

    applyTransferEventToTransferContext(ctx, {
      direction: "outgoing",
      event: "outgoing_progress",
      peer_did: "did:nxf:peer",
      session_id: "sess-1"
    });
    expect(ctx.localStage).toBe("sending");
  });

  it("clears transfer context when the outgoing transfer completes", () => {
    const ctx = sampleContext();
    applyTransferEventToTransferContext(ctx, {
      direction: "outgoing",
      event: "outgoing_pending",
      peer_did: "did:nxf:peer",
      session_id: "sess-1"
    });

    applyTransferEventToTransferContext(ctx, {
      direction: "outgoing",
      event: "outgoing_completed",
      peer_did: "did:nxf:peer",
      session_id: "sess-1"
    });

    expect(ctx.localStage).toBeNull();
    expect(ctx.outgoingDid).toBeNull();
    expect(ctx.outgoingSession).toBeNull();
  });

  it("clears stale non-packing state when snapshot has no live outgoing transfer", () => {
    const ctx = sampleContext();
    ctx.localStage = "approved";
    ctx.outgoingSession = "sess-1";

    reconcileTransferContextForPeer(ctx, "did:nxf:peer", null);

    expect(ctx.localStage).toBeNull();
    expect(ctx.outgoingDid).toBeNull();
  });

  it("keeps packing state until the first outgoing event arrives", () => {
    const ctx = sampleContext();

    reconcileTransferContextForPeer(ctx, "did:nxf:peer", null);

    expect(ctx.localStage).toBe("packing");
    resetTransferContextState(ctx);
    expect(ctx.localStage).toBeNull();
  });
});

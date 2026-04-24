export interface TransferContextState {
  outgoingDid: string | null;
  outgoingSession: string | null;
  lastPackedDid: string | null;
  sessionDid: Record<string, string>;
  localStage: "packing" | "preparing" | "pending" | "approved" | "sending" | null;
}

export interface TransferRuntimeEventLike {
  direction?: string | null;
  event: string;
  peer_did?: string | null;
  peer_canonical_did?: string | null;
  session_id?: string | null;
}

function normalizeDid(value: string | null | undefined): string | null {
  const trimmed = String(value || "").trim();
  return trimmed ? trimmed : null;
}

function normalizeSessionId(value: string | null | undefined): string | null {
  const trimmed = String(value || "").trim();
  return trimmed ? trimmed : null;
}

function isOutgoingTransferDirection(direction: string | null | undefined): boolean {
  const value = String(direction || "").trim().toLowerCase();
  return value === "outgoing" || value === "out";
}

export function resetTransferContextState(ctx: TransferContextState): void {
  ctx.outgoingDid = null;
  ctx.outgoingSession = null;
  ctx.lastPackedDid = null;
  ctx.localStage = null;
  ctx.sessionDid = Object.create(null);
}

export function applyTransferEventToTransferContext(
  ctx: TransferContextState,
  payload: TransferRuntimeEventLike
): void {
  if (!isOutgoingTransferDirection(payload.direction)) return;

  const did = normalizeDid(payload.peer_canonical_did || payload.peer_did);
  const sessionId = normalizeSessionId(payload.session_id);
  if (did) {
    ctx.outgoingDid = did;
  }
  if (sessionId) {
    ctx.outgoingSession = sessionId;
    if (did) {
      ctx.sessionDid[sessionId] = did;
    }
  }

  switch (payload.event) {
    case "outgoing_packing":
      ctx.localStage = "packing";
      break;
    case "outgoing_preparing":
      ctx.localStage = "preparing";
      break;
    case "outgoing_pending":
      ctx.localStage = "pending";
      break;
    case "outgoing_accepted":
      ctx.localStage = "approved";
      break;
    case "outgoing_progress":
      ctx.localStage = "sending";
      break;
    case "outgoing_completed":
    case "outgoing_rejected":
    case "outgoing_failed": {
      const resolvedDid = did || (sessionId ? ctx.sessionDid[sessionId] || null : null);
      if (!resolvedDid || !ctx.outgoingDid || ctx.outgoingDid === resolvedDid) {
        resetTransferContextState(ctx);
      } else if (sessionId) {
        delete ctx.sessionDid[sessionId];
        if (ctx.outgoingSession === sessionId) {
          ctx.outgoingSession = null;
        }
      }
      break;
    }
    default:
      break;
  }
}

export function reconcileTransferContextForPeer(
  ctx: TransferContextState,
  activeDid: string | null,
  latestOutgoing: TransferRuntimeEventLike | null
): void {
  const did = normalizeDid(activeDid);
  if (!did) return;

  if (latestOutgoing && normalizeDid(latestOutgoing.peer_canonical_did || latestOutgoing.peer_did) === did) {
    applyTransferEventToTransferContext(ctx, latestOutgoing);
    return;
  }

  if (ctx.outgoingDid === did && ctx.localStage && ctx.localStage !== "packing") {
    resetTransferContextState(ctx);
  }
}

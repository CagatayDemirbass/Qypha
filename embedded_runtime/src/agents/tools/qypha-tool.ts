import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { Type } from "@sinclair/typebox";
import { stringEnum } from "../schema/typebox.js";
import { AnyAgentTool, jsonResult, readStringParam, ToolInputError } from "./common.js";

const QYPHA_CONTROL_SOCKET_ENV = "QYPHA_COMPANION_CONTROL_SOCKET";
const QYPHA_CONTROL_TOKEN_ENV = "QYPHA_COMPANION_CONTROL_TOKEN";
const QYPHA_REQUESTER_ENV = "QYPHA_COMPANION_REQUESTER_AGENT";
const QYPHA_WORKSPACE_ENV = "QYPHA_RUNTIME_WORKSPACE_DIR";
const QYPHA_RECEIVE_DIR_DEFAULT_ENV = "QYPHA_RECEIVE_DIR_DEFAULT";
const QYPHA_RECEIVE_DIR_GLOBAL_ENV = "QYPHA_RECEIVE_DIR_GLOBAL";
const QYPHA_RECEIVE_DIR_EFFECTIVE_ENV = "QYPHA_RECEIVE_DIR_EFFECTIVE";
const QYPHA_RECEIVE_DIR_SOURCE_ENV = "QYPHA_RECEIVE_DIR_SOURCE";

const RECEIVE_DIR_TARGET_TYPES = ["global", "peer"] as const;
const SEND_TO_TARGET_TYPES = ["requester", "peer", "group"] as const;
const TRANSFER_TARGET_TYPES = ["requester", "peer", "group"] as const;

const QyphaEmptySchema = Type.Object({});

const QyphaPeersSchema = Type.Object({
  verbose: Type.Optional(
    Type.Boolean({
      description:
        "Set true to mirror `/peers -v` when you want the freshest full peer listing from the companion runtime.",
    }),
  ),
});

const QyphaSendSchema = Type.Object({
  message: Type.String({
    description:
      "Single encrypted chat message to broadcast to all currently connected Qypha peers.",
  }),
});

const QyphaSendToSchema = Type.Object({
  targetType: Type.Optional(
    stringEnum(SEND_TO_TARGET_TYPES, {
      description:
        'Optional. Use "requester" to reply to the inbound Qypha sender for this run, "peer" for a direct peer selector/DID, or "group" for a Qypha group_id. When this field is omitted and the run has a bound Qypha requester, the tool deterministically defaults to that requester.',
    }),
  ),
  target: Type.Optional(
    Type.String({
      description:
        'Required for "peer" and "group". For peers, pass a selector like "1" from qypha_peers or a DID. For groups, pass the group_id from qypha_groups.',
    }),
  ),
  message: Type.String({
    description: "Encrypted chat body to send to the chosen Qypha peer, group, or requester.",
  }),
});

const QyphaTransferSchema = Type.Object({
  targetType: Type.Optional(
    stringEnum(TRANSFER_TARGET_TYPES, {
      description:
        'Optional. Use "requester" to send the artifact back to the inbound Qypha sender for this run, "peer" for a direct peer selector/DID, or "group" for a Qypha group_id. When this field is omitted and the run has a bound Qypha requester, the tool deterministically defaults to that requester.',
    }),
  ),
  target: Type.Optional(
    Type.String({
      description:
        'Required for "peer" and "group". For peers, pass a selector like "1" from qypha_peers or a DID. For groups, pass the group_id from qypha_groups.',
    }),
  ),
  path: Type.String({
    description:
      "Absolute or workspace-relative filesystem path to the file or directory to transfer over Qypha.",
  }),
});

const QyphaDisconnectSchema = Type.Object({
  target: Type.String({
    description:
      "Peer selector or DID to disconnect. Prefer a DID for unambiguous targeting, or use a selector from qypha_peers.",
  }),
});

const QyphaReceiveDirSchema = Type.Object({
  targetType: Type.Optional(
    stringEnum(RECEIVE_DIR_TARGET_TYPES, {
      description:
        'Use "global" to change the default receive directory for all incoming files, or "peer" to set a receive directory for one sender only.',
    }),
  ),
  target: Type.Optional(
    Type.String({
      description:
        'Required when targetType is "peer". Pass a direct peer selector such as `1` from qypha_peers or a peer DID.',
    }),
  ),
  path: Type.Optional(
    Type.String({
      description:
        "Absolute or workspace-relative directory path to create/use for incoming transfers. Omit when you only want to inspect the current global receive directory.",
    }),
  ),
  reset: Type.Optional(
    Type.Boolean({
      description:
        "Set true to reset the targeted receive directory back to the default location. Do not combine with path.",
    }),
  ),
});

const QyphaDecisionSchema = Type.Object({
  selector: Type.Optional(
    Type.String({
      description:
        "Optional pending item selector. Depending on the pending item, this may be a peer selector, peer DID, group_id, manifest_id, or handshake member DID.",
    }),
  ),
});

const QyphaSingleTargetSchema = Type.Object({
  target: Type.String({
    description:
      "Peer selector, DID, member id, or group id required by this Qypha command. Use the matching discovery tool first when unsure.",
  }),
});

const QyphaGroupNameSchema = Type.Object({
  name: Type.String({
    description:
      "Human-readable group name. This may contain spaces and will be passed through to the Qypha companion runtime.",
  }),
});

const QyphaOptionalGroupNameSchema = Type.Object({
  name: Type.Optional(
    Type.String({
      description:
        "Optional group name. When omitted, the companion runtime chooses the default anonymous-group labeling flow.",
    }),
  ),
});

const QyphaGroupIdSchema = Type.Object({
  groupId: Type.String({
    description:
      "Mailbox group id from qypha_groups. Use the canonical group_id exactly as returned by the companion runtime.",
  }),
});

const QyphaOwnerSpecialIdSchema = Type.Object({
  ownerSpecialId: Type.String({
    description:
      "Anonymous group owner special id returned by qypha_groups or prior invite output, used to regenerate anonymous invites.",
  }),
});

const QyphaHandshakeSchema = Type.Object({
  memberDid: Type.String({
    description:
      "Group member DID that should receive or be affected by a direct-handshake request action.",
  }),
});

const QyphaHandshakeGroupSchema = Type.Object({
  groupId: Type.String({
    description:
      "Mailbox group id that scopes the handshake request to a specific durable group.",
  }),
  memberDid: Type.String({
    description:
      "Group member DID that should receive the direct-handshake request.",
  }),
});

const QyphaConnectSchema = Type.Object({
  code: Type.String({
    description:
      "Invite code to consume with Qypha `/connect`. Pass the invite string itself, not a file path.",
  }),
});

type QyphaControlRequest =
  | { op: "peers"; verbose?: boolean }
  | { op: "groups" }
  | { op: "whoami" }
  | { op: "send"; message: string }
  | { op: "send_to"; target: string; message: string }
  | { op: "disconnect"; target: string }
  | { op: "transfer_to_peer"; target: string; path: string }
  | { op: "transfer_to_group"; group_id: string; path: string }
  | { op: "receive_dir"; target?: string; path?: string; reset?: boolean }
  | { op: "accept"; selector?: string }
  | { op: "accept_always"; target: string }
  | { op: "accept_ask"; target: string }
  | { op: "reject"; selector?: string }
  | { op: "invite" }
  | { op: "group_normal"; name: string }
  | { op: "invite_group"; group_id: string }
  | { op: "group_anon"; name?: string }
  | { op: "invite_anon"; owner_special_id: string }
  | { op: "invite_handshake"; member_id: string }
  | { op: "invite_handshake_group"; group_id: string; member_id: string }
  | { op: "block"; selector?: string }
  | { op: "unblock"; member_id: string }
  | { op: "block_all_requests" }
  | { op: "unblock_all_requests" }
  | { op: "connect"; code: string }
  | { op: "kick_group_member"; member_id: string }
  | { op: "lock_group"; group_id: string }
  | { op: "unlock_group"; group_id: string }
  | { op: "leave_group"; group_id: string }
  | { op: "disband_group"; group_id: string }
  | { op: "quit" };

type QyphaPeer = {
  selector: string;
  name: string;
  did: string;
  peer_id?: string | null;
  status?: string;
};

type QyphaGroup = {
  group_id: string;
  group_name?: string | null;
  anonymous_group: boolean;
  anonymous_security_state?: string | null;
  join_locked: boolean;
  persistence: string;
  local_member_id?: string | null;
  owner_member_id?: string | null;
  owner_special_id?: string | null;
  known_member_ids: string[];
  mailbox_epoch: number;
  degraded?: boolean;
};

type QyphaWhoAmI = {
  name: string;
  did: string;
  peer_id: string;
  transport: string;
  iroh_id?: string | null;
  onion?: string | null;
  ip?: string | null;
  relay_routes?: number | null;
  direct_peers: number;
  groups: number;
};

type QyphaControlResponse = {
  ok: boolean;
  action: string;
  text?: string;
  lines?: string[];
  peers?: QyphaPeer[];
  groups?: QyphaGroup[];
  whoami?: QyphaWhoAmI | null;
  resolved_target?: string;
  invite_kind?: string;
  invite_code?: string;
  receive_dir_default?: string;
  receive_dir_global?: string;
  receive_dir_effective?: string;
  receive_dir_source?: string;
  receive_dir_peer_did?: string;
  receive_dir_peer_path?: string;
  error?: string;
};

type QyphaReceiveDirContext = {
  defaultDir: string;
  globalDir: string;
  effectiveDir: string;
  effectiveSource: string;
  requester?: string;
};

type QyphaReceiveDirMarkers = {
  globalDir?: string;
  peerDid?: string;
  peerPath?: string;
};

function quietLinkControlAvailable(): boolean {
  return Boolean(
    process.env[QYPHA_CONTROL_SOCKET_ENV]?.trim() &&
      process.env[QYPHA_CONTROL_TOKEN_ENV]?.trim(),
  );
}

function defaultQyphaReceiveDir(): string {
  const homeDir = process.env.HOME?.trim() || process.env.USERPROFILE?.trim() || ".";
  return path.join(homeDir, "Desktop", "received");
}

function readQyphaReceiveDirContext(): QyphaReceiveDirContext {
  const defaultDir =
    process.env[QYPHA_RECEIVE_DIR_DEFAULT_ENV]?.trim() || defaultQyphaReceiveDir();
  const globalDir = process.env[QYPHA_RECEIVE_DIR_GLOBAL_ENV]?.trim() || defaultDir;
  const effectiveDir = process.env[QYPHA_RECEIVE_DIR_EFFECTIVE_ENV]?.trim() || globalDir;
  const effectiveSource =
    process.env[QYPHA_RECEIVE_DIR_SOURCE_ENV]?.trim() ||
    (effectiveDir === globalDir ? (globalDir === defaultDir ? "default" : "global") : "peer");
  const requester = process.env[QYPHA_REQUESTER_ENV]?.trim();
  return {
    defaultDir,
    globalDir,
    effectiveDir,
    effectiveSource,
    requester: requester && requester !== "self" ? requester : undefined,
  };
}

function writeQyphaReceiveDirContext(context: QyphaReceiveDirContext): void {
  process.env[QYPHA_RECEIVE_DIR_DEFAULT_ENV] = context.defaultDir;
  process.env[QYPHA_RECEIVE_DIR_GLOBAL_ENV] = context.globalDir;
  process.env[QYPHA_RECEIVE_DIR_EFFECTIVE_ENV] = context.effectiveDir;
  process.env[QYPHA_RECEIVE_DIR_SOURCE_ENV] = context.effectiveSource;
}

function describeQyphaReceiveDirContext(): string {
  const context = readQyphaReceiveDirContext();
  return `Current run context: effective incoming files are expected at \`${context.effectiveDir}\` (source: ${context.effectiveSource}); global receive dir is \`${context.globalDir}\`; default fallback is \`${context.defaultDir}\`. If this tool changes the receive dir during the run, treat the tool result as the new source of truth.`;
}

function parseQyphaReceiveDirMarkers(lines: string[]): QyphaReceiveDirMarkers {
  const markers: QyphaReceiveDirMarkers = {};
  for (const line of lines) {
    if (line.startsWith("RECEIVE_DIR:")) {
      markers.globalDir = line.slice("RECEIVE_DIR:".length).trim();
      continue;
    }
    const peerMatch = line.match(/^RECEIVE_DIR_PEER:(did:[^:]+:[^:]+):(.*)$/);
    if (peerMatch) {
      markers.peerDid = peerMatch[1]?.trim();
      markers.peerPath = peerMatch[2]?.trim();
    }
  }
  return markers;
}

function nextQyphaEffectiveSource(
  pathValue: string,
  globalDir: string,
  defaultDir: string,
): string {
  if (pathValue === globalDir) {
    return globalDir === defaultDir ? "default" : "global";
  }
  if (pathValue === defaultDir) {
    return "default";
  }
  return "peer";
}

function enrichReceiveDirResponse(
  response: QyphaControlResponse,
  targetType: "global" | "peer",
): QyphaControlResponse {
  const context = readQyphaReceiveDirContext();
  const markers = parseQyphaReceiveDirMarkers(response.lines ?? []);
  let globalDir = context.globalDir;
  let effectiveDir = context.effectiveDir;
  let effectiveSource = context.effectiveSource;

  if (markers.globalDir) {
    globalDir = markers.globalDir;
    if (effectiveSource !== "peer") {
      effectiveDir = markers.globalDir;
      effectiveSource =
        markers.globalDir === context.defaultDir ? "default" : "global";
    }
  }

  if (targetType === "peer" && markers.peerDid && markers.peerPath) {
    if (context.requester && markers.peerDid === context.requester) {
      effectiveDir = markers.peerPath;
      effectiveSource = nextQyphaEffectiveSource(
        markers.peerPath,
        globalDir,
        context.defaultDir,
      );
    }
  }

  const nextContext: QyphaReceiveDirContext = {
    ...context,
    globalDir,
    effectiveDir,
    effectiveSource,
  };
  writeQyphaReceiveDirContext(nextContext);

  return {
    ...response,
    receive_dir_default: nextContext.defaultDir,
    receive_dir_global: nextContext.globalDir,
    receive_dir_effective: nextContext.effectiveDir,
    receive_dir_source: nextContext.effectiveSource,
    ...(markers.peerDid ? { receive_dir_peer_did: markers.peerDid } : {}),
    ...(markers.peerPath ? { receive_dir_peer_path: markers.peerPath } : {}),
  };
}

function requireQyphaControl(): { socketPath: string; token: string } {
  const socketPath = process.env[QYPHA_CONTROL_SOCKET_ENV]?.trim();
  const token = process.env[QYPHA_CONTROL_TOKEN_ENV]?.trim();
  if (!socketPath || !token) {
    throw new Error("Qypha companion control is unavailable for this embedded run.");
  }
  return { socketPath, token };
}

function requireSingleLineText(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new ToolInputError(`${label} required`);
  }
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new ToolInputError(`${label} contains forbidden control characters`);
  }
  return trimmed;
}

function requireToken(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new ToolInputError(`${label} required`);
  }
  if (/[\u0000-\u001f\u007f\s]/.test(trimmed)) {
    throw new ToolInputError(`${label} must not contain whitespace or control characters`);
  }
  return trimmed;
}

function readBooleanParam(
  params: Record<string, unknown>,
  key: string,
  defaultValue = false,
): boolean {
  return typeof params[key] === "boolean" ? params[key] : defaultValue;
}

function resolveRequesterTarget(): string {
  const requester = process.env[QYPHA_REQUESTER_ENV]?.trim();
  if (!requester || requester === "self") {
    throw new ToolInputError(
      'No Qypha requester is bound to this run. Use targetType="peer" or targetType="group" instead.',
    );
  }
  return requester;
}

async function resolveTransferPath(inputPath: string): Promise<string> {
  const raw = requireSingleLineText(inputPath, "path");
  const workspaceDir = process.env[QYPHA_WORKSPACE_ENV]?.trim();
  const candidate = path.isAbsolute(raw)
    ? path.normalize(raw)
    : path.resolve(workspaceDir || process.cwd(), raw);
  let resolved = candidate;
  try {
    resolved = await fs.realpath(candidate);
  } catch {
    throw new ToolInputError(`path not found: ${candidate}`);
  }
  let stats;
  try {
    stats = await fs.stat(resolved);
  } catch {
    throw new ToolInputError(`path not readable: ${resolved}`);
  }
  if (!stats.isFile() && !stats.isDirectory()) {
    throw new ToolInputError(`path must resolve to a file or directory: ${resolved}`);
  }
  return resolved;
}

function resolveReceiveDirPath(inputPath: string): string {
  const raw = requireSingleLineText(inputPath, "path");
  if (raw.startsWith("~")) {
    return raw;
  }
  const workspaceDir = process.env[QYPHA_WORKSPACE_ENV]?.trim();
  return path.isAbsolute(raw)
    ? path.normalize(raw)
    : path.resolve(workspaceDir || process.cwd(), raw);
}

function resolveTarget(
  params: Record<string, unknown>,
  targetTypeKey: "targetType",
  targetKey: "target",
): { targetType: "requester" | "peer" | "group"; target: string } {
  const rawTargetType = readStringParam(params, targetTypeKey, {
    required: false,
    label: "targetType",
  });
  const requester = process.env[QYPHA_REQUESTER_ENV]?.trim();
  const targetType = (rawTargetType ??
    (!readStringParam(params, targetKey, { required: false, label: "target" }) &&
    requester &&
    requester !== "self"
      ? "requester"
      : "")) as "requester" | "peer" | "group";
  if (!SEND_TO_TARGET_TYPES.includes(targetType)) {
    throw new ToolInputError(
      'targetType must be requester, peer, or group. When this run has a bound Qypha requester, you may omit targetType and target to default back to that requester.',
    );
  }
  if (targetType === "requester") {
    return { targetType, target: resolveRequesterTarget() };
  }
  const target = requireToken(
    readStringParam(params, targetKey, { required: true, label: "target" }),
    "target",
  );
  return { targetType, target };
}

async function callQyphaControl(
  request: QyphaControlRequest,
): Promise<QyphaControlResponse> {
  const { socketPath, token } = requireQyphaControl();
  const payload = JSON.stringify({ token, ...request });
  return await new Promise<QyphaControlResponse>((resolve, reject) => {
    let settled = false;
    let buffer = "";
    const socket = net.createConnection({ path: socketPath });
    const parseResponse = (raw: string) => {
      const response = JSON.parse(raw) as QyphaControlResponse;
      if (!response.ok) {
        throw new Error(response.error || "Qypha control request failed");
      }
      return response;
    };
    const finish = (fn: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      fn();
    };

    socket.setEncoding("utf8");
    socket.setTimeout(15_000);
    socket.on("connect", () => {
      socket.write(`${payload}\n`);
    });
    socket.on("data", (chunk: string | Buffer) => {
      buffer += String(chunk);
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex < 0) {
        return;
      }
      const line = buffer.slice(0, newlineIndex).trim();
      finish(() => {
        try {
          resolve(parseResponse(line));
        } catch (error) {
          reject(
            new Error(
              `Failed to parse Qypha control response: ${
                error instanceof Error ? error.message : String(error)
              }`,
            ),
          );
        } finally {
          socket.end();
        }
      });
    });
    socket.on("timeout", () => {
      finish(() => {
        socket.destroy();
        reject(new Error("Timed out waiting for Qypha control response"));
      });
    });
    socket.on("error", (error) => {
      finish(() => reject(new Error(`Qypha control socket error: ${error.message}`)));
    });
    socket.on("end", () => {
      if (settled) {
        return;
      }
      finish(() => {
        const trailing = buffer.trim();
        if (trailing) {
          try {
            resolve(parseResponse(trailing));
            return;
          } catch (error) {
            reject(
              new Error(
                `Failed to parse Qypha control response: ${
                  error instanceof Error ? error.message : String(error)
                }`,
              ),
            );
            return;
          }
        }
        reject(new Error("Qypha control socket closed before a response arrived"));
      });
    });
  });
}

export function createQyphaPeersTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Peers",
    name: "qypha_peers",
    ownerOnly: true,
    description:
      "List currently connected Qypha direct peers from the active companion runtime. Use this before qypha_sendto, qypha_transfer, qypha_disconnect, qypha_accept_always, or qypha_receive_dir when you need a fresh selector. The result includes a 1-based `selector` string that matches `/peers`, plus the peer name, DID, peer_id when available, and readiness status. Set `verbose=true` when you want the tool to mirror `/peers -v`.",
    parameters: QyphaPeersSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const response = await callQyphaControl({
        op: "peers",
        verbose: readBooleanParam(params, "verbose", false),
      });
      return jsonResult(response);
    },
  };
}

export function createQyphaGroupsTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Groups",
    name: "qypha_groups",
    ownerOnly: true,
    description:
      "List active Qypha mailbox groups from the active companion runtime. Use this before qypha_sendto or qypha_transfer when the recipient is a group. The result includes the canonical `group_id`, the optional display name, anonymity mode, join lock state, persistence, known member ids, and mailbox epoch.",
    parameters: QyphaEmptySchema,
    execute: async () => {
      const response = await callQyphaControl({ op: "groups" });
      return jsonResult(response);
    },
  };
}

export function createQyphaWhoAmITool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha WhoAmI",
    name: "qypha_whoami",
    ownerOnly: true,
    description:
      "Show the active companion Qypha identity details exactly as the network runtime reports them. Use this when the user asks which agent identity is currently online, which DID is active, or which transport/runtime identity the embedded agent should reference.",
    parameters: QyphaEmptySchema,
    execute: async () => {
      const response = await callQyphaControl({ op: "whoami" });
      return jsonResult(response);
    },
  };
}

export function createQyphaSendTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Send",
    name: "qypha_send",
    ownerOnly: true,
    description:
      "Broadcast one encrypted Qypha chat message to all currently connected direct peers. Use this only for text updates that should go to everyone at once. Do not use it for a single recipient, a specific group, or any file/folder transfer; use qypha_sendto or qypha_transfer for those cases.",
    parameters: QyphaSendSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const message = requireSingleLineText(
        readStringParam(params, "message", { required: true, label: "message" }),
        "message",
      );
      const response = await callQyphaControl({ op: "send", message });
      return jsonResult(response);
    },
  };
}

export function createQyphaReplyTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  const requester = process.env[QYPHA_REQUESTER_ENV]?.trim();
  if (!requester || requester === "self") {
    return null;
  }
  return {
    label: "Qypha Reply",
    name: "qypha_reply",
    ownerOnly: true,
    description:
      "Send one encrypted Qypha chat reply back to the current inbound requester for this run. This tool is only available when the embedded run was triggered by an incoming Qypha direct message, and it deterministically targets that requester without needing a peer selector, DID lookup, qypha_peers, or qypha_whoami.",
    parameters: QyphaSendSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const message = requireSingleLineText(
        readStringParam(params, "message", { required: true, label: "message" }),
        "message",
      );
      const response = await callQyphaControl({ op: "send_to", target: resolveRequesterTarget(), message });
      return jsonResult({
        ...response,
        targetType: "requester",
        resolved_target: resolveRequesterTarget(),
      });
    },
  };
}

export function createQyphaSendToTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha SendTo",
    name: "qypha_sendto",
    ownerOnly: true,
    description:
      'Send one encrypted Qypha chat message to a specific recipient. Use `targetType="peer"` with a peer selector such as `1` from qypha_peers or with a DID. Use `targetType="group"` with a `group_id` from qypha_groups. Use `targetType="requester"` when this run was triggered by an inbound Qypha direct message and the reply should go back to that sender. When a requester is bound to the current run, you may omit both `targetType` and `target` to deterministically reply back to that requester.',
    parameters: QyphaSendToSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const { target } = resolveTarget(params, "targetType", "target");
      const message = requireSingleLineText(
        readStringParam(params, "message", { required: true, label: "message" }),
        "message",
      );
      const response = await callQyphaControl({ op: "send_to", target, message });
      return jsonResult(response);
    },
  };
}

export function createQyphaReplyTransferTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  const requester = process.env[QYPHA_REQUESTER_ENV]?.trim();
  if (!requester || requester === "self") {
    return null;
  }
  return {
    label: "Qypha ReplyTransfer",
    name: "qypha_reply_transfer",
    ownerOnly: true,
    description:
      "Send an E2EE file or directory back to the current inbound Qypha requester for this run. This tool is only available when the embedded run was triggered by an incoming Qypha direct message, and it deterministically targets that requester without needing a peer selector, DID lookup, qypha_peers, or qypha_whoami.",
    parameters: Type.Object({
      path: Type.String({
        description:
          "Absolute or workspace-relative filesystem path to the file or directory that should be returned to the current Qypha requester.",
      }),
    }),
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const resolvedPath = await resolveTransferPath(
        readStringParam(params, "path", { required: true, label: "path" }),
      );
      const resolvedTarget = resolveRequesterTarget();
      const response = await callQyphaControl({
        op: "transfer_to_peer",
        target: resolvedTarget,
        path: resolvedPath,
      });
      return jsonResult({
        ...response,
        targetType: "requester",
        resolved_target: resolvedTarget,
        path: resolvedPath,
      });
    },
  };
}

export function createQyphaTransferTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Transfer",
    name: "qypha_transfer",
    ownerOnly: true,
    description:
      'Send an E2EE file or directory through the active Qypha companion runtime. The `path` may resolve to either a file or a folder. Use read/find/exec first if you need to locate the artifact on disk, then call this tool with the resolved path. Use `targetType="peer"` with a peer selector or DID, `targetType="group"` with a group_id, or `targetType="requester"` when the current run originated from an inbound Qypha direct message and the artifact should be sent back to that sender. When a requester is bound to the current run, you may omit both `targetType` and `target` to deterministically send the artifact back to that requester.',
    parameters: QyphaTransferSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const { targetType, target } = resolveTarget(params, "targetType", "target");
      const resolvedPath = await resolveTransferPath(
        readStringParam(params, "path", { required: true, label: "path" }),
      );
      const response =
        targetType === "group"
          ? await callQyphaControl({
              op: "transfer_to_group",
              group_id: target,
              path: resolvedPath,
            })
          : await callQyphaControl({
              op: "transfer_to_peer",
              target,
              path: resolvedPath,
            });
      return jsonResult({
        ...response,
        targetType,
        path: resolvedPath,
      });
    },
  };
}

export function createQyphaDisconnectTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Disconnect",
    name: "qypha_disconnect",
    ownerOnly: true,
    description:
      "Disconnect one Qypha direct peer and remove it from the auto-reconnect set. Use this only when the user explicitly wants to sever the current direct relationship. Pass a peer selector from qypha_peers or, preferably, the peer DID for a stable target.",
    parameters: QyphaDisconnectSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const target = requireToken(
        readStringParam(params, "target", { required: true, label: "target" }),
        "target",
      );
      const response = await callQyphaControl({ op: "disconnect", target });
      return jsonResult({
        ...response,
        resolved_target: target,
      });
    },
  };
}

export function createQyphaReceiveDirTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha ReceiveDir",
    name: "qypha_receive_dir",
    ownerOnly: true,
    description:
      'Inspect, set, or reset the Qypha receive directory used for incoming encrypted file transfers. Use `targetType="global"` to control the default receive directory for all senders, or `targetType="peer"` with a selector or DID to create/set a per-peer receive directory. Provide `path` to create or switch to that directory. Set `reset=true` to return the targeted receive directory to the default. When inspecting the current global configuration, omit both `path` and `reset`. ' +
      describeQyphaReceiveDirContext(),
    parameters: QyphaReceiveDirSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const inferredTargetType =
        readStringParam(params, "targetType", {
          required: false,
          label: "targetType",
        }) ?? (readStringParam(params, "target", { required: false, label: "target" }) ? "peer" : "global");
      if (!RECEIVE_DIR_TARGET_TYPES.includes(inferredTargetType as (typeof RECEIVE_DIR_TARGET_TYPES)[number])) {
        throw new ToolInputError('targetType must be "global" or "peer"');
      }
      const targetType = inferredTargetType as "global" | "peer";
      const reset = readBooleanParam(params, "reset", false);
      const rawPath = readStringParam(params, "path", { required: false, label: "path" });
      if (reset && rawPath) {
        throw new ToolInputError("path cannot be combined with reset=true");
      }
      const targetRaw = readStringParam(params, "target", { required: false, label: "target" });
      const target = targetRaw ? requireToken(targetRaw, "target") : undefined;
      if (targetType === "peer" && !target) {
        throw new ToolInputError('target required when targetType is "peer"');
      }
      if (targetType === "peer" && !reset && !rawPath) {
        throw new ToolInputError(
          'path required when targetType is "peer" unless you are resetting that peer receive directory',
        );
      }
      const receivePath = rawPath ? resolveReceiveDirPath(rawPath) : undefined;
      const response = await callQyphaControl({
        op: "receive_dir",
        ...(target ? { target } : {}),
        ...(receivePath ? { path: receivePath } : {}),
        ...(reset ? { reset: true } : {}),
      });
      const enrichedResponse = enrichReceiveDirResponse(response, targetType);
      return jsonResult({
        ...enrichedResponse,
        targetType,
        ...(target ? { resolved_target: target } : {}),
        ...(receivePath ? { path: receivePath } : {}),
        reset,
      });
    },
  };
}

export function createQyphaAcceptTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Accept",
    name: "qypha_accept",
    ownerOnly: true,
    description:
      "Inspect or approve pending Qypha inbound actions. With no selector, this lists pending incoming file transfers and direct-handshake approvals, similar to plain `/accept`. With `selector`, it approves the specified item. Depending on context, the selector may be a peer selector, peer DID, group_id, manifest_id, or handshake member DID exactly as Qypha reports it.",
    parameters: QyphaDecisionSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const selectorRaw = readStringParam(params, "selector", { required: false, label: "selector" });
      const selector = selectorRaw ? requireToken(selectorRaw, "selector") : undefined;
      const response = await callQyphaControl({
        op: "accept",
        ...(selector ? { selector } : {}),
      });
      return jsonResult({
        ...response,
        ...(selector ? { resolved_target: selector } : {}),
      });
    },
  };
}

export function createQyphaAcceptAlwaysTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha AcceptAlways",
    name: "qypha_accept_always",
    ownerOnly: true,
    description:
      "Set incoming transfer policy to ALWAYS_ACCEPT for one Qypha sender. Use this when the user explicitly wants future incoming files from a specific peer to be auto-approved without prompting. Pass a peer selector from qypha_peers or, preferably, the peer DID.",
    parameters: QyphaSingleTargetSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const target = requireToken(
        readStringParam(params, "target", { required: true, label: "target" }),
        "target",
      );
      const response = await callQyphaControl({ op: "accept_always", target });
      return jsonResult({
        ...response,
        resolved_target: target,
      });
    },
  };
}

export function createQyphaAcceptAskTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha AcceptAsk",
    name: "qypha_accept_ask",
    ownerOnly: true,
    description:
      "Set incoming transfer policy back to ASK_EVERY_TIME for one Qypha sender. Use this when the user no longer wants automatic file acceptance from a specific peer. Pass a peer selector from qypha_peers or, preferably, the peer DID.",
    parameters: QyphaSingleTargetSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const target = requireToken(
        readStringParam(params, "target", { required: true, label: "target" }),
        "target",
      );
      const response = await callQyphaControl({ op: "accept_ask", target });
      return jsonResult({
        ...response,
        resolved_target: target,
      });
    },
  };
}

export function createQyphaRejectTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Reject",
    name: "qypha_reject",
    ownerOnly: true,
    description:
      "Reject a pending Qypha item. With no selector, this mirrors plain `/reject` and only works when exactly one direct-handshake request is pending. With `selector`, reject the specific pending file transfer, manifest, group offer, or handshake member DID that Qypha reported.",
    parameters: QyphaDecisionSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const selectorRaw = readStringParam(params, "selector", { required: false, label: "selector" });
      const selector = selectorRaw ? requireToken(selectorRaw, "selector") : undefined;
      const response = await callQyphaControl({
        op: "reject",
        ...(selector ? { selector } : {}),
      });
      return jsonResult({
        ...response,
        ...(selector ? { resolved_target: selector } : {}),
      });
    },
  };
}

export function createQyphaInviteTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Invite",
    name: "qypha_invite",
    ownerOnly: true,
    description:
      "Generate a fresh direct-peer Qypha invite code from the active companion runtime. Use this when the user wants to onboard another peer into the direct chat network. The response may include the generated invite code so it can be shared back to the user or another agent.",
    parameters: QyphaEmptySchema,
    execute: async () => {
      const response = await callQyphaControl({ op: "invite" });
      return jsonResult(response);
    },
  };
}

export function createQyphaGroupNormalTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha GroupNormal",
    name: "qypha_group_normal",
    ownerOnly: true,
    description:
      "Create a reusable durable Qypha mailbox group, equivalent to `/group_normal`. Use this in the normal durable group plane when the user wants a named group that can persist and accept reusable group invites. This is not for Ghost-only anonymous groups.",
    parameters: QyphaGroupNameSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const name = requireSingleLineText(
        readStringParam(params, "name", { required: true, label: "name" }),
        "name",
      );
      const response = await callQyphaControl({ op: "group_normal", name });
      return jsonResult(response);
    },
  };
}

export function createQyphaInviteGroupTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha InviteGroup",
    name: "qypha_invite_group",
    ownerOnly: true,
    description:
      "Generate a fresh invite for an existing durable Qypha group, equivalent to `/invite_g`. Use a canonical group id from qypha_groups. This is only for durable groups, not Ghost-only anonymous groups.",
    parameters: QyphaGroupIdSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const groupId = requireToken(
        readStringParam(params, "groupId", { required: true, label: "groupId" }),
        "groupId",
      );
      const response = await callQyphaControl({ op: "invite_group", group_id: groupId });
      return jsonResult({
        ...response,
        resolved_target: groupId,
      });
    },
  };
}

export function createQyphaGroupAnonTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha GroupAnon",
    name: "qypha_group_anon",
    ownerOnly: true,
    description:
      "Create a Ghost-only anonymous mailbox group, equivalent to `/group_anon`. Use this only when the active companion runtime is operating in Ghost mode. You may provide an optional display name; otherwise Qypha uses its default anonymous-group flow.",
    parameters: QyphaOptionalGroupNameSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const rawName = readStringParam(params, "name", { required: false, label: "name" });
      const name = rawName ? requireSingleLineText(rawName, "name") : undefined;
      const response = await callQyphaControl({
        op: "group_anon",
        ...(name ? { name } : {}),
      });
      return jsonResult(response);
    },
  };
}

export function createQyphaInviteAnonTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha InviteAnon",
    name: "qypha_invite_anon",
    ownerOnly: true,
    description:
      "Regenerate an invite for an existing Ghost-only anonymous group, equivalent to `/invite_anon`. Pass the anonymous group owner special id returned by the group runtime.",
    parameters: QyphaOwnerSpecialIdSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const ownerSpecialId = requireToken(
        readStringParam(params, "ownerSpecialId", {
          required: true,
          label: "ownerSpecialId",
        }),
        "ownerSpecialId",
      );
      const response = await callQyphaControl({
        op: "invite_anon",
        owner_special_id: ownerSpecialId,
      });
      return jsonResult({
        ...response,
        resolved_target: ownerSpecialId,
      });
    },
  };
}

export function createQyphaInviteHandshakeTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha InviteHandshake",
    name: "qypha_invite_handshake",
    ownerOnly: true,
    description:
      "Send a direct-handshake request to one Qypha group member, equivalent to `/invite_h`. Use this only when the active runtime is not in Ghost mode. Pass the member DID exactly as Qypha reports it.",
    parameters: QyphaHandshakeSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const memberDid = requireToken(
        readStringParam(params, "memberDid", { required: true, label: "memberDid" }),
        "memberDid",
      );
      const response = await callQyphaControl({
        op: "invite_handshake",
        member_id: memberDid,
      });
      return jsonResult({
        ...response,
        resolved_target: memberDid,
      });
    },
  };
}

export function createQyphaInviteHandshakeGroupTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha InviteHandshakeGroup",
    name: "qypha_invite_handshake_group",
    ownerOnly: true,
    description:
      "Send a direct-handshake request scoped to a specific Qypha mailbox group, equivalent to `/invite_hg`. Use this when the user wants to target one group member from one durable group context. This command is disabled in Ghost mode.",
    parameters: QyphaHandshakeGroupSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const groupId = requireToken(
        readStringParam(params, "groupId", { required: true, label: "groupId" }),
        "groupId",
      );
      const memberDid = requireToken(
        readStringParam(params, "memberDid", { required: true, label: "memberDid" }),
        "memberDid",
      );
      const response = await callQyphaControl({
        op: "invite_handshake_group",
        group_id: groupId,
        member_id: memberDid,
      });
      return jsonResult({
        ...response,
        resolved_target: `${groupId}:${memberDid}`,
      });
    },
  };
}

export function createQyphaBlockTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Block",
    name: "qypha_block",
    ownerOnly: true,
    description:
      "Block direct-handshake requests from one Qypha member. With no selector, this mirrors plain `/block` and only works when exactly one direct trust offer is pending. With `selector`, pass the member DID you want to block.",
    parameters: QyphaDecisionSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const selectorRaw = readStringParam(params, "selector", { required: false, label: "selector" });
      const selector = selectorRaw ? requireToken(selectorRaw, "selector") : undefined;
      const response = await callQyphaControl({
        op: "block",
        ...(selector ? { selector } : {}),
      });
      return jsonResult({
        ...response,
        ...(selector ? { resolved_target: selector } : {}),
      });
    },
  };
}

export function createQyphaUnblockTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Unblock",
    name: "qypha_unblock",
    ownerOnly: true,
    description:
      "Remove the direct-handshake block for one Qypha member, equivalent to `/unblock`. Pass the group member DID that should be allowed to send direct-handshake requests again.",
    parameters: QyphaHandshakeSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const memberDid = requireToken(
        readStringParam(params, "memberDid", { required: true, label: "memberDid" }),
        "memberDid",
      );
      const response = await callQyphaControl({ op: "unblock", member_id: memberDid });
      return jsonResult({
        ...response,
        resolved_target: memberDid,
      });
    },
  };
}

export function createQyphaBlockAllRequestsTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha BlockAllRequests",
    name: "qypha_block_all_requests",
    ownerOnly: true,
    description:
      "Enable the global shield that blocks all incoming direct-handshake requests, equivalent to `/block_all_r`. Use this only when the user explicitly wants to pause every new direct-handshake request.",
    parameters: QyphaEmptySchema,
    execute: async () => {
      const response = await callQyphaControl({ op: "block_all_requests" });
      return jsonResult(response);
    },
  };
}

export function createQyphaUnblockAllRequestsTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha UnblockAllRequests",
    name: "qypha_unblock_all_requests",
    ownerOnly: true,
    description:
      "Disable the global shield that blocks all incoming direct-handshake requests, equivalent to `/unblock_all_r`. Use this when the user wants to allow direct-handshake requests again for the whole runtime.",
    parameters: QyphaEmptySchema,
    execute: async () => {
      const response = await callQyphaControl({ op: "unblock_all_requests" });
      return jsonResult(response);
    },
  };
}

export function createQyphaConnectTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Connect",
    name: "qypha_connect",
    ownerOnly: true,
    description:
      "Consume a Qypha invite code and connect to the remote peer or group, equivalent to `/connect`. Pass the invite code itself. Use this only when the user explicitly wants to join or connect via a received invite.",
    parameters: QyphaConnectSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const code = requireSingleLineText(
        readStringParam(params, "code", { required: true, label: "code" }),
        "code",
      );
      const response = await callQyphaControl({ op: "connect", code });
      return jsonResult(response);
    },
  };
}

export function createQyphaKickGroupMemberTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha KickGroupMember",
    name: "qypha_kick_group_member",
    ownerOnly: true,
    description:
      "Remove one member from a Qypha mailbox group, equivalent to `/kick_g`. Use this only when the user explicitly wants the group owner to eject a member. Pass the group member selector or DID exactly as Qypha expects.",
    parameters: QyphaHandshakeSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const memberDid = requireToken(
        readStringParam(params, "memberDid", { required: true, label: "memberDid" }),
        "memberDid",
      );
      const response = await callQyphaControl({
        op: "kick_group_member",
        member_id: memberDid,
      });
      return jsonResult({
        ...response,
        resolved_target: memberDid,
      });
    },
  };
}

export function createQyphaLockGroupTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha LockGroup",
    name: "qypha_lock_group",
    ownerOnly: true,
    description:
      "Lock a Qypha mailbox group against new joins, equivalent to `/lock_g`. Use a canonical group id from qypha_groups. Only the mailbox group owner can do this.",
    parameters: QyphaGroupIdSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const groupId = requireToken(
        readStringParam(params, "groupId", { required: true, label: "groupId" }),
        "groupId",
      );
      const response = await callQyphaControl({ op: "lock_group", group_id: groupId });
      return jsonResult({
        ...response,
        resolved_target: groupId,
      });
    },
  };
}

export function createQyphaUnlockGroupTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha UnlockGroup",
    name: "qypha_unlock_group",
    ownerOnly: true,
    description:
      "Unlock a Qypha mailbox group so new joins are allowed again, equivalent to `/unlock_g`. Use a canonical group id from qypha_groups. Only the mailbox group owner can do this.",
    parameters: QyphaGroupIdSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const groupId = requireToken(
        readStringParam(params, "groupId", { required: true, label: "groupId" }),
        "groupId",
      );
      const response = await callQyphaControl({ op: "unlock_group", group_id: groupId });
      return jsonResult({
        ...response,
        resolved_target: groupId,
      });
    },
  };
}

export function createQyphaLeaveGroupTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha LeaveGroup",
    name: "qypha_leave_group",
    ownerOnly: true,
    description:
      "Leave and forget a joined Qypha mailbox group, equivalent to `/leave_g`. Use this only when the user explicitly wants the current agent to leave the specified group.",
    parameters: QyphaGroupIdSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const groupId = requireToken(
        readStringParam(params, "groupId", { required: true, label: "groupId" }),
        "groupId",
      );
      const response = await callQyphaControl({ op: "leave_group", group_id: groupId });
      return jsonResult({
        ...response,
        resolved_target: groupId,
      });
    },
  };
}

export function createQyphaDisbandGroupTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha DisbandGroup",
    name: "qypha_disband_group",
    ownerOnly: true,
    description:
      "Disband a Qypha mailbox group, equivalent to `/disband`. Use this only when the user explicitly wants the mailbox group owner to permanently tear down the specified group.",
    parameters: QyphaGroupIdSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const groupId = requireToken(
        readStringParam(params, "groupId", { required: true, label: "groupId" }),
        "groupId",
      );
      const response = await callQyphaControl({ op: "disband_group", group_id: groupId });
      return jsonResult({
        ...response,
        resolved_target: groupId,
      });
    },
  };
}

export function createQyphaQuitTool(): AnyAgentTool | null {
  if (!quietLinkControlAvailable()) {
    return null;
  }
  return {
    label: "Qypha Quit",
    name: "qypha_quit",
    ownerOnly: true,
    description:
      "Stop the active Qypha companion runtime, equivalent to `/quit`. Use this only when the user explicitly wants to shut down the current AI network runtime session.",
    parameters: QyphaEmptySchema,
    execute: async () => {
      const response = await callQyphaControl({ op: "quit" });
      return jsonResult(response);
    },
  };
}

export function createQyphaTools(): AnyAgentTool[] {
  return [
    createQyphaPeersTool(),
    createQyphaGroupsTool(),
    createQyphaWhoAmITool(),
    createQyphaSendTool(),
    createQyphaReplyTool(),
    createQyphaSendToTool(),
    createQyphaReplyTransferTool(),
    createQyphaTransferTool(),
    createQyphaDisconnectTool(),
    createQyphaReceiveDirTool(),
    createQyphaAcceptTool(),
    createQyphaAcceptAlwaysTool(),
    createQyphaAcceptAskTool(),
    createQyphaRejectTool(),
    createQyphaInviteTool(),
    createQyphaGroupNormalTool(),
    createQyphaInviteGroupTool(),
    createQyphaGroupAnonTool(),
    createQyphaInviteAnonTool(),
    createQyphaInviteHandshakeTool(),
    createQyphaInviteHandshakeGroupTool(),
    createQyphaBlockTool(),
    createQyphaUnblockTool(),
    createQyphaBlockAllRequestsTool(),
    createQyphaUnblockAllRequestsTool(),
    createQyphaConnectTool(),
    createQyphaKickGroupMemberTool(),
    createQyphaLockGroupTool(),
    createQyphaUnlockGroupTool(),
    createQyphaLeaveGroupTool(),
    createQyphaDisbandGroupTool(),
    createQyphaQuitTool(),
  ].filter((tool): tool is AnyAgentTool => tool != null);
}

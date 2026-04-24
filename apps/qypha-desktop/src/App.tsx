import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { allowClipboardCopy } from "./privacy";
import { buildDirectConversationTimeline } from "./conversationTimeline";
import { buildGroupConversationTimeline } from "./groupConversationTimeline";
import {
  hydrateMissingMailboxGroupSnapshot,
  snapshotContainsMailboxGroup
} from "./groupHydration";
import {
  shouldKeepImplicitDmConversation,
  shouldRenderConversationInList
} from "./conversationPresence";
import {
  defaultConversationKey,
  sortConversationsByActivity
} from "./conversationOrdering";
import {
  isGroupConversationActivityVisibleAfterDelete,
  isGroupConversationRemovalKind,
  latestGroupConversationActivityTsMs,
  shouldHideDeletedGroupConversation
} from "./groupConversationVisibility";
import { resolveMailboxGroupConversationLabel } from "./groupLabels";
import {
  applyTransferEventToTransferContext,
  reconcileTransferContextForPeer,
  resetTransferContextState
} from "./transferUiState";

type ConversationType = "group" | "dm";
type MessageDirection = "in" | "out";
type InviteHubSection = "direct" | "group";
type PendingTransferKind = "file" | "folder";
type RuntimeActionKind = "create" | "start" | "stop";
type AgentType = "human" | "ai";
type AiProviderKind = "ollama" | "openai" | "claude" | "gemini";

type TransportMode = "internet" | "tor" | "tcp";
type LogMode = "safe" | "ghost";

const IS_MACOS = /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent);

function sanitizeListenPortInput(value: string): string {
  return value.replace(/[^\d]/g, "").slice(0, 5);
}

function resolveListenPort(value: string, fallback = 9090): number {
  const trimmed = sanitizeListenPortInput(value).trim();
  if (!trimmed) return fallback;
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(65535, Math.trunc(parsed)));
}

function lastItem<T>(items: readonly T[]): T | null {
  return items.length > 0 ? items[items.length - 1] : null;
}

interface PeerSnapshot {
  name: string;
  did: string;
  contact_did?: string | null;
  status: string;
  auto_reconnect: boolean;
}

interface PendingContactRequestSnapshot {
  name: string;
  did: string;
  contact_did?: string | null;
  canonical_did?: string | null;
  ts_ms: number;
}

interface RuntimeSnapshot {
  running: boolean;
  pid: number | null;
  started_at: string | null;
  contact_did?: string | null;
  selected_peer: string | null;
  last_error: string | null;
  mode: string;
  transport: string;
  listen_port: number;
  peers: PeerSnapshot[];
  mailbox_groups: MailboxGroupSnapshot[];
  pending_approvals: string[];
  pending_contact_requests?: PendingContactRequestSnapshot[];
  recent_logs: string[];
  transfer_events?: TransferRuntimeEvent[];
  direct_events?: DirectMessageRuntimeEvent[];
  peer_events?: DirectPeerRuntimeEvent[];
  group_events?: GroupMailboxRuntimeEvent[];
  handshake_request_policy?: HandshakeRequestPolicySnapshot;
  incoming_connect_policy?: IncomingConnectPolicySnapshot;
  latest_invite_code?: string | null;
  latest_invite_revision?: number | null;
  latest_group_invite_code?: string | null;
  latest_group_invite_revision?: number | null;
  receive_dir?: string | null;
  ghost_handoffs?: GhostHandoffSnapshot[];
}

interface MailboxGroupSnapshot {
  group_id: string;
  group_name?: string | null;
  anonymous_group: boolean;
  anonymous_security_state?: string | null;
  persistence: "memory_only" | "encrypted_disk" | string;
  local_member_id?: string | null;
  owner_member_id?: string | null;
  owner_special_id?: string | null;
  known_member_ids: string[];
  mailbox_epoch: number;
  join_locked?: boolean;
  degraded?: boolean;
}

interface GroupMailboxRuntimeEvent {
  kind: string;
  group_id: string;
  group_name?: string | null;
  anonymous_group: boolean;
  manifest_id?: string | null;
  sender_member_id?: string | null;
  message?: string | null;
  filename?: string | null;
  size_bytes?: number | null;
  member_id?: string | null;
  member_display_name?: string | null;
  invite_code?: string | null;
  mailbox_epoch?: number | null;
  kicked_member_id?: string | null;
  ts_ms?: number | null;
}

interface DirectMessageRuntimeEvent {
  direction: "incoming" | "outgoing" | string;
  peer_did: string;
  peer_contact_did?: string | null;
  peer_canonical_did?: string | null;
  peer_name: string;
  message: string;
  ts_ms?: number | null;
}

interface DirectPeerRuntimeEvent {
  event: "connected" | "reconnecting" | "disconnected" | string;
  did: string;
  contact_did?: string | null;
  canonical_did?: string | null;
  name: string;
  peer_id?: string | null;
  status?: string | null;
  reason?: string | null;
  ts_ms?: number | null;
}

interface HandshakeRequestPolicySnapshot {
  block_all: boolean;
  blocked_member_ids: string[];
}

interface IncomingConnectPolicySnapshot {
  block_all: boolean;
  blocked_dids: string[];
}

interface AgentCard {
  name: string;
  agent_type: AgentType | string;
  ai_provider?: string | null;
  ai_model?: string | null;
  ai_role?: string | null;
  ai_access_mode?: string | null;
  mode: string;
  transport: string;
  listen_port: number;
  config_path: string | null;
  config_present: boolean;
  running: boolean;
  pid: number | null;
  last_error: string | null;
  incoming_connect_block_all: boolean;
  incoming_connect_policy_known: boolean;
}

interface AppSnapshot {
  active_agent: string | null;
  agents: AgentCard[];
  runtime: RuntimeSnapshot | null;
}

interface AiModelOption {
  id: string;
  label: string;
  source: string;
}

interface AiProviderCatalog {
  ollama_host: string;
  ollama_models: AiModelOption[];
  ollama_available: boolean;
  ollama_error?: string | null;
}

interface AiProviderSecretStatus {
  provider: string;
  provider_label: string;
  env_var_hint?: string | null;
  configured: boolean;
  storage_label: string;
}

interface AgentSkillRecord {
  id: string;
  name: string;
  file_path: string;
  markdown: string;
  updated_at_ms: number;
}

interface AiAgentThreadMessage {
  role: string;
  content: string;
  ts_ms: number;
}

interface AiAgentThreadState {
  ai_agent: string;
  requester_agent?: string | null;
  ai_provider?: string | null;
  ai_model?: string | null;
  ai_role: string;
  ai_access_mode: string;
  messages: AiAgentThreadMessage[];
}

interface RuntimeLineEvent {
  agent: string;
}

function normalizeLogMode(mode: string | null | undefined): LogMode {
  return String(mode || "").trim().toLowerCase() === "ghost" ? "ghost" : "safe";
}

function normalizeAgentType(agentType: string | null | undefined): AgentType {
  return String(agentType || "").trim().toLowerCase() === "ai" ? "ai" : "human";
}

function providerLabel(provider: string | null | undefined): string {
  switch (String(provider || "").trim().toLowerCase()) {
    case "ollama":
      return "Ollama";
    case "openai":
      return "OpenAI";
    case "claude":
      return "Claude";
    case "gemini":
      return "Gemini";
    default:
      return provider || "Provider";
  }
}

function localAiDid(agentName: string): string {
  return `local-ai:${String(agentName || "").trim()}`;
}

function isLocalAiDid(value: string | null | undefined): boolean {
  return String(value || "").startsWith("local-ai:");
}

function aiAgentNameFromDid(value: string | null | undefined): string | null {
  if (!isLocalAiDid(value)) return null;
  const trimmed = String(value || "").slice("local-ai:".length).trim();
  return trimmed || null;
}

function aiControlConversationTitle(agentName: string): string {
  return `Control • ${String(agentName || "").trim()}`;
}

function aiRoleLabel(role: string | null | undefined): string {
  switch (String(role || "").trim().toLowerCase()) {
    case "":
    case "general":
      return "general";
    default:
      return String(role || "").trim();
  }
}

function aiAccessModeLabel(mode: string | null | undefined): string {
  switch (String(mode || "").trim().toLowerCase()) {
    case "":
    case "full":
    case "full_access":
      return "full access";
    default:
      return String(mode || "").trim();
  }
}

const AI_PROVIDER_OPTIONS: AiProviderKind[] = ["ollama", "openai", "claude", "gemini"];

function providerDefaultModelId(provider: string | null | undefined): string {
  switch (String(provider || "").trim().toLowerCase()) {
    case "openai":
      return "gpt-5.4";
    case "claude":
      return "claude-sonnet-4-6";
    case "gemini":
      return "gemini-2.5-flash";
    default:
      return "";
  }
}

function providerDefaultModelLabel(provider: string | null | undefined): string {
  switch (String(provider || "").trim().toLowerCase()) {
    case "openai":
      return "GPT-5.4";
    case "claude":
      return "Claude Sonnet 4.6";
    case "gemini":
      return "Gemini 2.5 Flash";
    default:
      return "";
  }
}

function logModeForTransport(transport: TransportMode, mode: LogMode): LogMode {
  return transport === "tor" ? mode : "safe";
}

function transportLabel(transport: string | null | undefined): string {
  switch (String(transport || "").trim().toLowerCase()) {
    case "tcp":
    case "lan":
      return "LAN";
    case "tor":
      return "Tor";
    case "internet":
      return "Internet";
    case "unknown":
      return "state only";
    default:
      return transport || "state only";
  }
}

function agentTypeTitle(agentType: AgentType): string {
  return agentType === "human" ? "Human Agent" : "AI Agent";
}

function agentTypeDescription(agentType: AgentType): string {
  return agentType === "human"
    ? "Create and run a local Qypha node with transport, mode, port, and receive-directory controls."
    : "Create an AI profile with provider, model, transport, mode, port, and access settings for assisted conversations.";
}

function providerNeedsApiKey(provider: string | null | undefined): boolean {
  return String(provider || "").trim().toLowerCase() !== "ollama";
}

function providerApiKeyPlaceholder(provider: string | null | undefined): string {
  switch (String(provider || "").trim().toLowerCase()) {
    case "openai":
      return "sk-...";
    case "claude":
      return "sk-ant-...";
    case "gemini":
      return "AIza...";
    default:
      return "Enter API key";
  }
}

function providerStatusTone(ok: boolean | null): "ok" | "warn" | "subtle" {
  if (ok === null) return "subtle";
  return ok ? "ok" : "warn";
}

interface NamedGroupMailboxRuntimeEvent {
  agent: string;
  event: GroupMailboxRuntimeEvent;
}

interface GhostRuntimeEvent {
  agent: string;
  event: "incoming_chat" | "invite_code" | string;
  sender?: string | null;
  message?: string | null;
  kind?: "direct" | "group" | string | null;
  code?: string | null;
  revision?: number | null;
}

interface GhostHandoffSnapshot {
  handoff_id: string;
  peer_did: string;
  peer_contact_did?: string | null;
  peer_canonical_did?: string | null;
  peer_name: string;
  filename: string;
  created_at_ms: number;
}

interface TransferRuntimeEvent {
  agent: string;
  event: string;
  direction: "incoming" | "outgoing" | string;
  peer_did?: string | null;
  peer_contact_did?: string | null;
  peer_canonical_did?: string | null;
  peer_name?: string | null;
  session_id?: string | null;
  filename?: string | null;
  reason?: string | null;
  handoff_id?: string | null;
  group_id?: string | null;
  group_name?: string | null;
  transferred_chunks?: number | null;
  total_chunks?: number | null;
  transferred_bytes?: number | null;
  total_bytes?: number | null;
  percent?: number | null;
  ts_ms?: number | null;
}

interface TransferPickerSelection {
  path: string;
  is_dir: boolean;
}

interface LatestGroupInviteContext {
  groupId: string | null;
  groupName: string | null;
  invalidatesPrevious?: boolean;
  previousEpoch?: number | null;
  currentEpoch?: number | null;
}

type GhostHandoffState = "staged" | "exported" | "discarded";

interface ChatMessage {
  direction: MessageDirection;
  sender: string;
  text: string;
  seq?: number;
  tsMs?: number;
  isTransfer?: boolean;
  transferKey?: string;
  transferStage?: string;
  handoffId?: string;
  handoffState?: GhostHandoffState;
  handoffFileName?: string | null;
  localPending?: boolean;
}

interface Conversation {
  key: string;
  type: ConversationType;
  title: string;
  did: string | null;
  messages: ChatMessage[];
  isExplicit?: boolean;
  isPeerListed?: boolean;
}

interface PendingDeleteState {
  agentName: string | null;
  key: string;
  label: string;
  did: string | null;
  groupId?: string | null;
  mode: "chat" | "group_chat" | "full" | "disconnect" | "group_leave" | "group_disband";
}

interface PendingAgentDestroyState {
  mode: "single" | "all";
  agentName: string | null;
}

interface PendingGroupKickState {
  groupId: string;
  groupLabel: string;
  memberId: string;
  memberLabel: string;
}

interface TransferContext {
  outgoingDid: string | null;
  outgoingSession: string | null;
  lastPackedDid: string | null;
  sessionDid: Record<string, string>;
  localStage: "packing" | "preparing" | "pending" | "approved" | "sending" | null;
}

interface TransferFeedItem {
  kind: "incoming" | "outgoing" | "error";
  text: string;
}

interface PendingGroupFileOffer {
  manifest_id: string;
  group_id: string;
  group_name?: string | null;
  anonymous_group: boolean;
  sender_member_id?: string | null;
  member_display_name?: string | null;
  filename?: string | null;
  size_bytes?: number | null;
  message?: string | null;
  ts_ms?: number | null;
}

interface PendingIncomingTransferOffer {
  transfer_key: string;
  did: string;
  peer_label: string;
  filename?: string | null;
  session_id?: string | null;
  ts_ms?: number | null;
}

interface LocalGroupOutgoingMessage {
  groupId: string;
  text: string;
  tsMs: number;
  isTransfer?: boolean;
}

interface GroupConversationRenderState {
  deletedCutoffByGroupId: Map<string, number>;
  hiddenGroupIds: Set<string>;
  removedGroupIds: Set<string>;
}

// Platform-aware: workspace root is resolved from the Rust backend at startup.
// Fallback to a sensible default only if backend call hasn't completed yet.
let workspaceRoot = ".";
const defaultConfig = "";
const POLL_IDLE_MS = 170;
const POLL_TRANSFER_MS = 120;
const PEER_REFRESH_MS = 10000;
const GHOST_SCRUB_INTERVAL_MS = 5000;
const GROUP_HANDSHAKE_INVITE_COOLDOWN_MS = 60_000;

function stripAnsi(text: string): string {
  return String(text || "").replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, "");
}

function stripRuntimePrefix(line: string): string {
  return line
    .replace(/^[A-Za-z0-9_-]+(?:\[[^\]]+\])?\s*>\s*/, "")
    .replace(/^\d{4}-\d{2}-\d{2}T\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+/, "")
    .replace(/^\d{4}-\d{2}-\d{2}T\S+\s+/, "")
    .replace(/^\[stderr\]\s+/, "")
    .trim();
}

function transferEventFeedback(payload: TransferRuntimeEvent): { text: string; isError: boolean } | null {
  const peer = payload.peer_name || payload.peer_contact_did || payload.peer_did || "peer";
  const file = payload.filename ? ` • ${fileNameFromPath(payload.filename)}` : "";
  const reason = payload.reason ? ` (${payload.reason})` : "";
  switch (payload.event) {
    case "outgoing_packing":
      return { text: `Packing file for transfer${file}`, isError: false };
    case "outgoing_preparing":
      return { text: `Preparing secure transfer${file}`, isError: false };
    case "outgoing_pending":
      return { text: `Waiting for ${peer} to accept transfer${file}`, isError: false };
    case "outgoing_accepted":
      return { text: `${peer} accepted transfer${file}`, isError: false };
    case "outgoing_rejected":
      return { text: `${peer} rejected transfer${file}${reason}`, isError: true };
    case "outgoing_completed":
      return { text: `Transfer completed to ${peer}${file}`, isError: false };
    case "incoming_pending":
      return { text: `Incoming transfer request from ${peer}${file}`, isError: false };
    case "incoming_accepted":
      return { text: `Incoming transfer accepted from ${peer}${file}`, isError: false };
    case "incoming_rejected":
      return { text: `Incoming transfer rejected from ${peer}${file}${reason}`, isError: true };
    case "incoming_staged":
      return { text: `Secure handoff ready from ${peer}${file}`, isError: false };
    case "incoming_exported":
      return { text: `Secure handoff exported${file}`, isError: false };
    case "incoming_discarded":
      return { text: `Secure handoff discarded${file}`, isError: false };
    case "incoming_completed":
      return { text: `Incoming transfer completed from ${peer}${file}`, isError: false };
    case "incoming_failed":
      return { text: `Incoming transfer failed from ${peer}${file}${reason}`, isError: true };
    case "outgoing_progress":
    case "incoming_progress":
      return null;
    default:
      return null;
  }
}

function canonicalDidForDirectMessageEvent(event: DirectMessageRuntimeEvent): string {
  return String(event.peer_canonical_did || event.peer_did || "").trim();
}

function visibleDidForDirectMessageEvent(event: DirectMessageRuntimeEvent): string {
  return String(event.peer_contact_did || event.peer_did || "").trim();
}

function canonicalDidForPeerRuntimeEvent(event: DirectPeerRuntimeEvent): string {
  return String(event.canonical_did || event.did || "").trim();
}

function visibleDidForPeerRuntimeEvent(event: DirectPeerRuntimeEvent): string {
  return String(event.contact_did || event.did || "").trim();
}

function canonicalDidForTransferEvent(event: TransferRuntimeEvent): string {
  return String(event.peer_canonical_did || event.peer_did || "").trim();
}

function visibleDidForTransferEvent(event: TransferRuntimeEvent): string {
  return String(event.peer_contact_did || event.peer_did || "").trim();
}

function canonicalDidForGhostHandoff(handoff: GhostHandoffSnapshot): string {
  return String(handoff.peer_canonical_did || handoff.peer_did || "").trim();
}

function visibleDidForGhostHandoff(handoff: GhostHandoffSnapshot): string {
  return String(handoff.peer_contact_did || handoff.peer_did || "").trim();
}

function formatByteCount(value: number | null | undefined): string {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "size unknown";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes: Uint8Array): string {
  if (!bytes.length) return "";
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    value /= 58n;
  }
  let leadingZeroes = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeroes += 1;
  }
  return `${"1".repeat(leadingZeroes)}${encoded || "1"}`;
}

function canonicalDidToContactDid(value: string | null | undefined): string {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (raw.startsWith("did:qypha:")) return raw;
  if (!raw.startsWith("did:nxf:")) return raw;
  const suffix = raw.slice("did:nxf:".length);
  if (!suffix || suffix.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(suffix)) {
    return raw;
  }
  const bytes = new Uint8Array(suffix.length / 2);
  for (let i = 0; i < suffix.length; i += 2) {
    bytes[i / 2] = parseInt(suffix.slice(i, i + 2), 16);
  }
  return `did:qypha:${encodeBase58(bytes)}`;
}

function isDid(value: string | null | undefined): boolean {
  const raw = String(value || "").trim();
  return !!raw && (raw.startsWith("did:qypha:") || raw.startsWith("did:nxf:"));
}

function looksLikeGroupId(value: string | null | undefined): boolean {
  const raw = String(value || "").trim();
  return !!raw && /^(grp_|gmbx_|group:)[A-Za-z0-9:_-]+$/.test(raw);
}

function groupConversationKey(groupId: string): string {
  return `group:${groupId}`;
}

function groupIdFromConversationKey(key: string | null | undefined): string | null {
  const raw = String(key || "").trim();
  if (!raw.startsWith("group:")) return null;
  const groupId = raw.slice("group:".length);
  return looksLikeGroupId(groupId) ? groupId : null;
}

function sameGroupRuntimeEvent(a: GroupMailboxRuntimeEvent, b: GroupMailboxRuntimeEvent): boolean {
  return (
    a.kind === b.kind &&
    a.group_id === b.group_id &&
    (a.manifest_id || "") === (b.manifest_id || "") &&
    (a.ts_ms || 0) === (b.ts_ms || 0) &&
    (a.message || "") === (b.message || "") &&
    (a.filename || "") === (b.filename || "") &&
    (a.sender_member_id || "") === (b.sender_member_id || "") &&
    (a.member_id || "") === (b.member_id || "") &&
    (a.invite_code || "") === (b.invite_code || "") &&
    (a.kicked_member_id || "") === (b.kicked_member_id || "")
  );
}

function isPeerOnlineStatus(status: string | null | undefined): boolean {
  const s = String(status || "").toLowerCase();
  if (!s) return false;
  return s.includes("connected") || s.includes("ready") || s.includes("online");
}

function peerPanelStatusRank(status: string | null | undefined): number {
  const s = String(status || "").toLowerCase();
  if (s.includes("online") || s.includes("connected") || s.includes("ready")) return 0;
  if (s.includes("connecting") || s.includes("reconnecting")) return 1;
  if (s.includes("offline")) return 2;
  return 3;
}

/// Clean up raw connection strings used as peer names in Tor mode.
/// e.g. "target=kd5ro...onion port=9090 peer_did=did:nxf:4a04..." → "kd5ro...onion"
function cleanPeerName(raw: string, did?: string): string {
  if (!raw) return did ? maskDidShort(did) : "unknown";
  // If name contains "target=" it's a raw Tor connection string
  if (raw.includes("target=") || raw.includes("peer_did=")) {
    // Try to extract just the onion address
    const onionMatch = raw.match(/target=([^\s]+\.onion)/);
    if (onionMatch) {
      const onion = onionMatch[1];
      // Return shortened onion: first 8 chars
      return onion.length > 16 ? onion.slice(0, 8) + "…" + onion.slice(-6) : onion;
    }
    // Fallback: extract the first meaningful token
    const targetMatch = raw.match(/target=([^\s]+)/);
    if (targetMatch) return targetMatch[1].slice(0, 16) + "…";
  }
  // If name is unreasonably long (>40 chars), truncate
  if (raw.length > 40) return raw.slice(0, 20) + "…";
  return raw;
}

function maskDidShort(did: string): string {
  const visibleDid = canonicalDidToContactDid(did);
  if (!visibleDid || visibleDid.length < 20) return visibleDid || "unknown";
  if (visibleDid.startsWith("did:qypha:")) {
    return visibleDid.slice(0, 22) + "…" + visibleDid.slice(-8);
  }
  return visibleDid.slice(0, 12) + "…" + visibleDid.slice(-4);
}

function directMessageEvents(runtime: RuntimeSnapshot | null): DirectMessageRuntimeEvent[] {
  return (runtime?.direct_events || [])
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => !!event.peer_did?.trim() && !!event.message?.trim())
    .sort((a, b) => {
      const aTs = a.event.ts_ms || 0;
      const bTs = b.event.ts_ms || 0;
      if (aTs !== bTs) return aTs - bTs;
      return a.index - b.index;
    })
    .map(({ event }) => event);
}

function peerRuntimeEvents(runtime: RuntimeSnapshot | null): DirectPeerRuntimeEvent[] {
  return (runtime?.peer_events || [])
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => !!event.did?.trim())
    .sort((a, b) => {
      const aTs = a.event.ts_ms || 0;
      const bTs = b.event.ts_ms || 0;
      if (aTs !== bTs) return aTs - bTs;
      return a.index - b.index;
    })
    .map(({ event }) => event);
}

function firstInviteToken(raw: string): string | null {
  const cleaned = stripAnsi(raw || "");
  const matches = cleaned.match(/[A-Za-z0-9_-]{80,}/g);
  if (!matches?.length) return null;
  return matches.sort((a, b) => b.length - a.length)[0] || null;
}

function normalizeInviteCode(raw: string): string {
  const token = firstInviteToken(raw);
  if (token) return token;
  return stripAnsi(raw || "").replace(/\s+/g, "").trim();
}

function isStructuredTransferLogLine(line: string): boolean {
  return stripAnsi(String(line || "")).includes("TRANSFER_EVENT ");
}

function collapseRuntimeLogLines(lines: string[]): string[] {
  const collapsed: string[] = [];
  let previous = "";
  let previousKey = "";
  let repeatCount = 0;

  const progressKeyForLine = (line: string): string | null => {
    const normalized = stripRuntimePrefix(stripAnsi(line)).replace(/\s+/g, " ").trim();
    if (/^(Receiving|Sending|Fast sending|Fast receiving): \[\d+\/\d+\]/i.test(normalized)) {
      return normalized.split(":")[0].trim().toLowerCase();
    }
    return null;
  };

  const flush = () => {
    if (!previous) return;
    collapsed.push(repeatCount > 1 ? `${previous} [x${repeatCount}]` : previous);
  };

  for (const rawLine of lines) {
    const line = stripRuntimePrefix(stripAnsi(String(rawLine || ""))).trimEnd();
    if (!line) continue;
    const progressKey = progressKeyForLine(line);
    const currentKey = progressKey ? `progress:${progressKey}` : line;
    if (progressKey && currentKey === previousKey) {
      previous = line;
      repeatCount = 1;
      continue;
    }
    if (currentKey === previousKey) {
      repeatCount += 1;
      continue;
    }
    flush();
    previous = line;
    previousKey = currentKey;
    repeatCount = 1;
  }

  flush();
  return collapsed;
}

function formatTransferEventProgress(payload: TransferRuntimeEvent): string | null {
  const chunks =
    typeof payload.transferred_chunks === "number" && typeof payload.total_chunks === "number"
      ? `${payload.transferred_chunks}/${payload.total_chunks} chunks`
      : null;
  const bytes =
    typeof payload.transferred_bytes === "number" && typeof payload.total_bytes === "number"
      ? `${(payload.transferred_bytes / (1024 * 1024)).toFixed(1)}/${(payload.total_bytes / (1024 * 1024)).toFixed(1)} MB`
      : null;
  const percent = typeof payload.percent === "number" ? `${payload.percent}%` : null;
  const parts = [chunks, bytes].filter(Boolean);
  if (!parts.length && !percent) return null;
  return percent ? `${parts.join(" • ")} (${percent})`.trim() : parts.join(" • ");
}

function transferEventFileLabel(filename: string | null | undefined): string {
  const value = String(filename || "").trim();
  if (!value) return "";
  return fileNameFromPath(value);
}

function transferEventKey(payload: TransferRuntimeEvent, did: string): string {
  const base =
    payload.session_id?.trim() ||
    `${payload.direction || "x"}:${did}:${transferEventFileLabel(payload.filename) || "file"}`;
  return base;
}

function maskDidForUi(did: string, masked: boolean): string {
  const visibleDid = canonicalDidToContactDid(did);
  if (!masked || !isDid(visibleDid)) return visibleDid;
  const head = visibleDid.startsWith("did:qypha:") ? visibleDid.slice(0, 22) : visibleDid.slice(0, 20);
  const tail = visibleDid.startsWith("did:qypha:") ? visibleDid.slice(-8) : visibleDid.slice(-8);
  return `${head}…${tail}`;
}

function fileNameFromPath(pathValue: string): string {
  const normalized = String(pathValue || "").trim().replace(/\\/g, "/");
  if (!normalized) return "";
  const parts = normalized.split("/");
  return parts[parts.length - 1] || normalized;
}

function pendingTransferLabel(kind: PendingTransferKind, pathValue: string): string {
  const prefix = kind === "folder" ? "Folder" : "File";
  return `${prefix}: ${fileNameFromPath(pathValue)}`;
}

function findLastMessageIndex(
  messages: ChatMessage[],
  predicate: (message: ChatMessage) => boolean
): number {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (predicate(messages[i])) return i;
  }
  return -1;
}

function isOutgoingTransferDirection(direction: string | null | undefined): boolean {
  const normalized = String(direction || "").trim().toLowerCase();
  return normalized === "out" || normalized === "outgoing";
}

function matchesIncomingTransferDirection(direction: string | null | undefined): boolean {
  const normalized = String(direction || "").trim().toLowerCase();
  return normalized === "in" || normalized === "incoming";
}

async function scrubBrowserResidue(): Promise<void> {
  try {
    localStorage.clear();
  } catch {}
  try {
    sessionStorage.clear();
  } catch {}
  try {
    if ("caches" in window) {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    }
  } catch {}
  try {
    const anyIndexedDb = indexedDB as IDBFactory & { databases?: () => Promise<Array<{ name?: string }>> };
    if (anyIndexedDb.databases) {
      const dbs = await anyIndexedDb.databases();
      for (const db of dbs) {
        if (db?.name) {
          try {
            indexedDB.deleteDatabase(db.name);
          } catch {}
        }
      }
    }
  } catch {}
}

async function clearClipboardBestEffort(): Promise<void> {
  try {
    await navigator.clipboard.writeText("");
  } catch {}
}

export default function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const snapshotRef = useRef<AppSnapshot | null>(null);
  const [activeAgentName, setActiveAgentName] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string>("");
  const [feedbackError, setFeedbackError] = useState<boolean>(false);
  const [renderEpoch, setRenderEpoch] = useState<number>(0);
  const [runtimeActionPending, setRuntimeActionPending] = useState<RuntimeActionKind | null>(null);

  const [agentName, setAgentName] = useState<string>("a");
  const [agentType, setAgentType] = useState<AgentType>("human");
  const [aiProvider, setAiProvider] = useState<AiProviderKind>("ollama");
  const [aiModel, setAiModel] = useState<string>("");
  const [aiRole, setAiRole] = useState<string>("general");
  const [ollamaCatalog, setOllamaCatalog] = useState<AiProviderCatalog | null>(null);
  const [ollamaCatalogLoading, setOllamaCatalogLoading] = useState<boolean>(false);
  const [aiProviderApiKeyInput, setAiProviderApiKeyInput] = useState<string>("");
  const [aiProviderSecretStatus, setAiProviderSecretStatus] = useState<AiProviderSecretStatus | null>(null);
  const [aiProviderSecretLoading, setAiProviderSecretLoading] = useState<boolean>(false);
  const [aiProviderSecretSaving, setAiProviderSecretSaving] = useState<boolean>(false);
  const [aiProviderSecretStatusCache, setAiProviderSecretStatusCache] = useState<Record<string, AiProviderSecretStatus>>({});
  const [agentSkills, setAgentSkills] = useState<AgentSkillRecord[]>([]);
  const [agentSkillsLoading, setAgentSkillsLoading] = useState<boolean>(false);
  const [agentSkillSaving, setAgentSkillSaving] = useState<boolean>(false);
  const [agentSkillDeletingId, setAgentSkillDeletingId] = useState<string | null>(null);
  const [selectedAgentSkillId, setSelectedAgentSkillId] = useState<string | null>(null);
  const [agentSkillNameInput, setAgentSkillNameInput] = useState<string>("");
  const [agentSkillMarkdownInput, setAgentSkillMarkdownInput] = useState<string>("");
  const [transport, setTransport] = useState<TransportMode>("internet");
  const [logMode, setLogMode] = useState<LogMode>("safe");
  const [listenPort, setListenPort] = useState<number>(9090);
  const [listenPortInput, setListenPortInput] = useState<string>("9090");
  const [passphrase, setPassphrase] = useState<string>("");
  const [configPath, setConfigPath] = useState<string>(defaultConfig);

  const [messageInput, setMessageInput] = useState<string>("");
  const [pendingFilePath, setPendingFilePath] = useState<string>("");
  const [pendingTransferKind, setPendingTransferKind] = useState<PendingTransferKind>("file");
  const [conversationFilter, setConversationFilter] = useState<string>("");
  const [inviteCodeInput, setInviteCodeInput] = useState<string>("");
  const [didConnectInput, setDidConnectInput] = useState<string>("");
  const [latestInviteCode, setLatestInviteCode] = useState<string>("");
  const [latestGroupInviteCode, setLatestGroupInviteCode] = useState<string>("");
  const [latestGroupInviteContext, setLatestGroupInviteContext] = useState<LatestGroupInviteContext | null>(null);
  const [groupInviteName, setGroupInviteName] = useState<string>("");
  const [inviteHubSection, setInviteHubSection] = useState<InviteHubSection>("direct");
  const [selectedInviteGroupId, setSelectedInviteGroupId] = useState<string | null>(null);

  const [openConversationMenuKey, setOpenConversationMenuKey] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<PendingDeleteState | null>(null);
  const [pendingAgentDestroy, setPendingAgentDestroy] = useState<PendingAgentDestroyState | null>(null);
  const [pendingGroupKick, setPendingGroupKick] = useState<PendingGroupKickState | null>(null);
  const [transferSubmitLock, setTransferSubmitLock] = useState<boolean>(false);
  const [composerMenuOpen, setComposerMenuOpen] = useState<boolean>(false);
  const [transferApprovalActionKey, setTransferApprovalActionKey] = useState<string | null>(null);
  const [contactRequestActionDid, setContactRequestActionDid] = useState<string | null>(null);
  const [handoffActionId, setHandoffActionId] = useState<string | null>(null);
  const [groupOfferActionId, setGroupOfferActionId] = useState<string | null>(null);
  const [groupMembersPanelOpen, setGroupMembersPanelOpen] = useState<boolean>(false);

  const [maskDid, setMaskDid] = useState<boolean>(false);
  const [receiveDirInput, setReceiveDirInput] = useState<string>("");
  const [receiveDirSaved, setReceiveDirSaved] = useState<boolean>(false);

  const conversationStoreRef = useRef<Map<string, Map<string, Conversation>>>(new Map());
  const lastHydratedAgentRef = useRef<string | null>(null);
  const activeConversationByAgentRef = useRef<Map<string, string>>(new Map());
  const selectedPeerByAgentRef = useRef<Map<string, string>>(new Map());
  const selectedGroupByAgentRef = useRef<Map<string, string>>(new Map());
  const localGroupOutgoingByAgentRef = useRef<Map<string, LocalGroupOutgoingMessage[]>>(new Map());
  const groupHandshakeInviteCooldownByAgentRef = useRef<Map<string, Map<string, number>>>(new Map());
  const transferPolicyByAgentRef = useRef<Map<string, Map<string, "ask" | "always">>>(new Map());
  const senderDidCacheByAgentRef = useRef<Map<string, Map<string, string>>>(new Map());
  const transferContextByAgentRef = useRef<Map<string, TransferContext>>(new Map());
  const deletedConversationDidsByAgentRef = useRef<Map<string, Set<string>>>(new Map());
  const deletedGroupConversationIdsByAgentRef = useRef<Map<string, Map<string, number>>>(new Map());
  const lastPeerRefreshAtByAgentRef = useRef<Map<string, number>>(new Map());
  const lastGroupBootstrapAtByAgentRef = useRef<Map<string, number>>(new Map());
  const lastPeerSessionSyncByAgentRef = useRef<Map<string, string>>(new Map());
  const lastGroupSessionSyncByAgentRef = useRef<Map<string, string>>(new Map());
  const lastAutoOpenedDidByAgentRef = useRef<Map<string, string>>(new Map());
  const lastConnectedLineKeyByAgentRef = useRef<Map<string, string>>(new Map());
  const modeByAgentRef = useRef<Map<string, LogMode>>(new Map());
  const messageSeqByAgentRef = useRef<Map<string, number>>(new Map());
  const refreshInFlightRef = useRef<boolean>(false);
  const inviteActionInFlightRef = useRef<boolean>(false);
  const eventRefreshTimerRef = useRef<number | null>(null);
  const lastMissingGroupRefreshRef = useRef<string>("");
  const lastGhostScrubAtRef = useRef<number>(0);
  const inviteHubRef = useRef<HTMLElement | null>(null);
  const conversationsCardRef = useRef<HTMLElement | null>(null);
  const chatThreadRef = useRef<HTMLDivElement | null>(null);
  const stickToBottomRef = useRef<boolean>(true);
  const forceScrollToBottomRef = useRef<boolean>(false);

  function setUiFeedback(message: string, isError = false): void {
    setFeedback(message || "");
    setFeedbackError(isError);
  }

  function getAgentKey(agent: string | null): string {
    return agent || "__none__";
  }

  function runtimeForAgent(agent: string | null): RuntimeSnapshot | null {
    const snapshot = snapshotRef.current;
    if (!agent || snapshot?.active_agent !== agent) return null;
    return snapshot?.runtime || null;
  }

  function isGhostAgent(agent: string | null): boolean {
    if (!agent) return false;
    if (modeByAgentRef.current.get(agent) === "ghost") return true;
    if (snapshotRef.current?.active_agent === agent && snapshotRef.current?.runtime?.mode === "ghost") {
      return true;
    }
    return false;
  }

  function hasOutgoingTransferForUi(runtimeValue: RuntimeSnapshot | null, agent: string | null): boolean {
    const ctx = transferContextForAgent(agent);
    if (ctx.outgoingSession || ctx.localStage) {
      return true;
    }
    const latestOutgoing = lastItem(
      [...(runtimeValue?.transfer_events || [])]
        .filter((event) => event.direction === "outgoing" || event.direction === "out")
        .sort((a, b) => (a.ts_ms || 0) - (b.ts_ms || 0))
    );
    if (!latestOutgoing) return false;
    return latestOutgoing.event !== "outgoing_completed" && latestOutgoing.event !== "outgoing_rejected";
  }

  function ensureDerivedConfigPath(currentName: string, currentMode: LogMode): string {
    const normalized = (currentName || "agent").toLowerCase().replace(/\s+/g, "_");
    const derivedPath = `${workspaceRoot}/agent-configs/qypha_${normalized}.toml`;
    if (currentMode === "ghost") return "";
    return derivedPath;
  }

  function conversationMapForAgent(agent: string | null): Map<string, Conversation> {
    const key = getAgentKey(agent);
    let map = conversationStoreRef.current.get(key);
    if (!map) {
      map = new Map<string, Conversation>();
      conversationStoreRef.current.set(key, map);
    }
    return map;
  }

  function activeConversationKeyForAgent(agent: string | null): string {
    const key = getAgentKey(agent);
    const current = activeConversationByAgentRef.current.get(key);
    if (current) return current;
    return defaultConversationKey([...conversationMapForAgent(agent).values()]);
  }

  function setActiveConversationKey(agent: string | null, keyValue: string): void {
    const key = getAgentKey(agent);
    if (!keyValue) {
      activeConversationByAgentRef.current.delete(key);
      return;
    }
    activeConversationByAgentRef.current.set(key, keyValue);
  }

  function selectedPeerForAgent(agent: string | null): string | null {
    const key = getAgentKey(agent);
    return selectedPeerByAgentRef.current.get(key) || null;
  }

  function setSelectedPeerForAgent(agent: string | null, did: string | null): void {
    const key = getAgentKey(agent);
    if (!did) {
      selectedPeerByAgentRef.current.delete(key);
      return;
    }
    selectedPeerByAgentRef.current.set(key, did);
  }

  function selectedGroupForAgent(agent: string | null): string | null {
    const key = getAgentKey(agent);
    return selectedGroupByAgentRef.current.get(key) || null;
  }

  function setSelectedGroupForAgent(agent: string | null, groupId: string | null): void {
    const key = getAgentKey(agent);
    if (!groupId) {
      selectedGroupByAgentRef.current.delete(key);
      return;
    }
    selectedGroupByAgentRef.current.set(key, groupId);
  }

  function senderDidCache(agent: string | null): Map<string, string> {
    const key = getAgentKey(agent);
    let map = senderDidCacheByAgentRef.current.get(key);
    if (!map) {
      map = new Map<string, string>();
      senderDidCacheByAgentRef.current.set(key, map);
    }
    return map;
  }

  function localGroupOutgoingForAgent(agent: string | null): LocalGroupOutgoingMessage[] {
    const key = getAgentKey(agent);
    let items = localGroupOutgoingByAgentRef.current.get(key);
    if (!items) {
      items = [];
      localGroupOutgoingByAgentRef.current.set(key, items);
    }
    return items;
  }

  function handshakeInviteCooldownsForAgent(agent: string | null): Map<string, number> {
    const key = getAgentKey(agent);
    let map = groupHandshakeInviteCooldownByAgentRef.current.get(key);
    if (!map) {
      map = new Map<string, number>();
      groupHandshakeInviteCooldownByAgentRef.current.set(key, map);
    }
    return map;
  }

  function rememberGroupHandshakeInviteCooldown(agent: string | null, memberId: string): void {
    const trimmed = memberId.trim();
    if (!trimmed) return;
    const now = Date.now();
    const cooldowns = handshakeInviteCooldownsForAgent(agent);
    cooldowns.set(trimmed, now + GROUP_HANDSHAKE_INVITE_COOLDOWN_MS);
  }

  function remainingGroupHandshakeInviteCooldownMs(agent: string | null, memberId: string): number {
    const trimmed = memberId.trim();
    if (!trimmed) return 0;
    const cooldowns = handshakeInviteCooldownsForAgent(agent);
    const expiresAt = cooldowns.get(trimmed) || 0;
    if (!expiresAt) return 0;
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      cooldowns.delete(trimmed);
      return 0;
    }
    return remaining;
  }

  function rememberLocalGroupOutgoing(
    agent: string | null,
    groupId: string,
    text: string,
    isTransfer = false
  ): number {
    const tsMs = Date.now();
    const items = localGroupOutgoingForAgent(agent);
    items.push({ groupId, text, tsMs, isTransfer });
    const cutoff = tsMs - 30 * 60 * 1000;
    while (items.length > 400 || (items[0] && items[0].tsMs < cutoff)) {
      items.shift();
    }
    return tsMs;
  }

  function transferContextForAgent(agent: string | null): TransferContext {
    const key = getAgentKey(agent);
    let ctx = transferContextByAgentRef.current.get(key);
    if (!ctx) {
      ctx = {
        outgoingDid: null,
        outgoingSession: null,
        lastPackedDid: null,
        sessionDid: Object.create(null),
        localStage: null
      };
      transferContextByAgentRef.current.set(key, ctx);
    }
    return ctx;
  }

  function transferPolicyMapForAgent(agent: string | null): Map<string, "ask" | "always"> {
    const key = getAgentKey(agent);
    let map = transferPolicyByAgentRef.current.get(key);
    if (!map) {
      map = new Map<string, "ask" | "always">();
      transferPolicyByAgentRef.current.set(key, map);
    }
    return map;
  }

  function deletedConversationSetForAgent(agent: string | null): Set<string> {
    const key = getAgentKey(agent);
    let set = deletedConversationDidsByAgentRef.current.get(key);
    if (!set) {
      set = new Set<string>();
      deletedConversationDidsByAgentRef.current.set(key, set);
    }
    return set;
  }

  function deletedGroupConversationMapForAgent(agent: string | null): Map<string, number> {
    const key = getAgentKey(agent);
    let map = deletedGroupConversationIdsByAgentRef.current.get(key);
    if (!map) {
      map = new Map<string, number>();
      deletedGroupConversationIdsByAgentRef.current.set(key, map);
    }
    return map;
  }

  function isConversationDeleted(agent: string | null, did: string | null): boolean {
    if (!did) return false;
    return deletedConversationSetForAgent(agent).has(did);
  }

  function isGroupConversationDeleted(agent: string | null, groupId: string | null): boolean {
    if (!groupId) return false;
    return deletedGroupConversationMapForAgent(agent).has(groupId);
  }

  function markConversationDeleted(agent: string | null, did: string | null): void {
    if (!did) return;
    deletedConversationSetForAgent(agent).add(did);
  }

  function deletedGroupConversationAt(agent: string | null, groupId: string | null): number | null {
    if (!groupId) return null;
    return deletedGroupConversationMapForAgent(agent).get(groupId) || null;
  }

  function markGroupConversationDeleted(
    agent: string | null,
    groupId: string | null,
    deletedAtMs = Date.now()
  ): void {
    if (!groupId) return;
    deletedGroupConversationMapForAgent(agent).set(groupId, deletedAtMs);
  }

  function clearConversationDeleted(agent: string | null, did: string | null): void {
    if (!did) return;
    deletedConversationSetForAgent(agent).delete(did);
  }

  function clearGroupConversationDeleted(agent: string | null, groupId: string | null): void {
    if (!groupId) return;
    deletedGroupConversationMapForAgent(agent).delete(groupId);
  }

  function getActiveConversation(agent: string | null): Conversation | null {
    const map = conversationMapForAgent(agent);
    const key = activeConversationKeyForAgent(agent);
    return map.get(key) || null;
  }

  function ensureConversation(
    map: Map<string, Conversation>,
    key: string,
    type: ConversationType,
    title: string,
    did: string | null = null,
    explicit = false
  ): void {
    // Don't recreate deleted conversations — fixes the bug where
    // rebuildConversations() would re-add a conversation from log lines
    // after the user deleted it from the sidebar.
    if (did && isConversationDeleted(activeAgentName, did)) return;
    if (!did && key.startsWith("dm:") && isConversationDeleted(activeAgentName, key.replace("dm:", ""))) return;
    const groupId = type === "group" ? groupIdFromConversationKey(key) : null;
    if (groupId && isGroupConversationDeleted(activeAgentName, groupId)) return;

    const current = map.get(key);
    if (!current) {
      map.set(key, {
        key,
        type,
        title,
        did,
        messages: [],
        isExplicit: explicit,
        isPeerListed: false
      });
      return;
    }
    current.title = title;
    if (did) current.did = did;
    if (explicit) current.isExplicit = true;
  }

  function syncPeerConversationMetadata(
    runtime: RuntimeSnapshot | null,
    agent: string | null,
    map: Map<string, Conversation>
  ): void {
    for (const conv of map.values()) {
      if (conv.type === "dm") {
        conv.isPeerListed = false;
      }
    }

    for (const peer of runtime?.peers || []) {
      senderDidCache(agent).set(peer.name.toLowerCase(), peer.did);
      const key = `dm:${peer.did}`;
      ensureConversation(map, key, "dm", cleanPeerName(peer.name, peer.did), peer.did);
      const conv = map.get(key);
      if (conv) {
        conv.isPeerListed = true;
      }
    }

    for (const conv of map.values()) {
      if (conv.type !== "dm" || !conv.did) continue;
      const peer = runtime?.peers.find((candidate) => candidate.did === conv.did) || null;
      if (peer?.name?.trim()) {
        conv.title = cleanPeerName(peer.name.trim(), conv.did);
      }
    }
  }

  function pruneImplicitEmptyDmConversations(
    agent: string | null,
    map: Map<string, Conversation>
  ): void {
    const activeKey = activeConversationKeyForAgent(agent);
    for (const [key, conv] of [...map.entries()]) {
      if (conv.type !== "dm") continue;
      if (shouldKeepImplicitDmConversation(conv, key === activeKey)) continue;
      map.delete(key);
    }
  }

  function appendConversationMessage(
    agent: string | null,
    map: Map<string, Conversation>,
    key: string,
    message: ChatMessage
  ): void {
    const conv = map.get(key);
    if (!conv) return;
    const agentKey = getAgentKey(agent);
    const counter = messageSeqByAgentRef.current.get(agentKey) || 0;
    const nextSeq = message.seq && message.seq > 0 ? message.seq : counter + 1;
    const nextTsMs =
      typeof message.tsMs === "number" && Number.isFinite(message.tsMs)
        ? message.tsMs
        : Date.now();
    if (nextSeq > counter) {
      messageSeqByAgentRef.current.set(agentKey, nextSeq);
    }
    conv.messages.push({ ...message, seq: nextSeq, tsMs: nextTsMs });
    if (conv.messages.length > 400) conv.messages.shift();
  }


  function sameDirectMessageForUiAck(pending: ChatMessage, delivered: ChatMessage): boolean {
    if (pending.direction !== "out" || delivered.direction !== "out") return false;
    if (pending.isTransfer || delivered.isTransfer) return false;
    if (pending.text !== delivered.text) return false;
    const pendingTs = typeof pending.tsMs === "number" ? pending.tsMs : 0;
    const deliveredTs = typeof delivered.tsMs === "number" ? delivered.tsMs : 0;
    if (!pendingTs || !deliveredTs) return true;
    return Math.abs(deliveredTs - pendingTs) <= 5 * 60 * 1000;
  }

  function mergePendingDirectMessages(
    previousMap: Map<string, Conversation>,
    nextMap: Map<string, Conversation>
  ): void {
    for (const [key, previous] of previousMap.entries()) {
      if (previous.type !== "dm" || !previous.did) continue;
      const next = nextMap.get(key);
      if (!next || next.type !== "dm") continue;

      const pendingMessages = previous.messages.filter((message) => message.localPending && !message.isTransfer);
      if (!pendingMessages.length) continue;

      const consumedDelivered = new Set<number>();
      for (const pending of pendingMessages) {
        const deliveredIdx = next.messages.findIndex((message, index) => {
          if (consumedDelivered.has(index)) return false;
          return sameDirectMessageForUiAck(pending, message);
        });
        if (deliveredIdx >= 0) {
          consumedDelivered.add(deliveredIdx);
          continue;
        }
        next.messages.push({ ...pending });
      }

      next.messages.sort((a, b) => {
        const aTs = typeof a.tsMs === "number" ? a.tsMs : 0;
        const bTs = typeof b.tsMs === "number" ? b.tsMs : 0;
        if (aTs !== bTs) return aTs - bTs;
        const aSeq = typeof a.seq === "number" ? a.seq : 0;
        const bSeq = typeof b.seq === "number" ? b.seq : 0;
        return aSeq - bSeq;
      });
      while (next.messages.length > 400) next.messages.shift();
    }
  }

  function focusConversationsCard(): void {
    const node = conversationsCardRef.current;
    if (!node) return;
    window.requestAnimationFrame(() => {
      node.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function focusInviteHub(section: InviteHubSection, groupId: string | null = null): void {
    setInviteHubSection(section);
    if (section === "group" && groupId) {
      setSelectedInviteGroupId(groupId);
    }
    if (
      section === "group" &&
      snapshotRef.current?.runtime?.running &&
      (snapshotRef.current?.runtime?.mailbox_groups?.length || 0) === 0
    ) {
      void invokeOrThrow<AppSnapshot>("runtime_list_groups")
        .then((next) => applySnapshot(next, true))
        .catch(() => {
          // best-effort hydrate when opening Group Management
        });
    }
    const node = inviteHubRef.current;
    if (!node) return;
    window.requestAnimationFrame(() => {
      node.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function isLocallyOwnedMailboxGroup(group: MailboxGroupSnapshot | null | undefined): boolean {
    if (!group) return false;
    if (group.anonymous_group) {
      return !!group.owner_special_id;
    }
    return !!group.local_member_id && group.owner_member_id === group.local_member_id;
  }

  function clearSensitiveUiMemory(): void {
    setPassphrase("");
    setMessageInput("");
    setPendingFilePath("");
    setPendingTransferKind("file");
    setInviteCodeInput("");
    setLatestInviteCode("");
    setLatestGroupInviteCode("");
    setLatestGroupInviteContext(null);
    setInviteHubSection("direct");
    setSelectedInviteGroupId(null);
    setReceiveDirInput("");
    setReceiveDirSaved(false);
    setHandoffActionId(null);

    conversationStoreRef.current.clear();
    activeConversationByAgentRef.current.clear();
    selectedPeerByAgentRef.current.clear();
    selectedGroupByAgentRef.current.clear();
    localGroupOutgoingByAgentRef.current.clear();
    groupHandshakeInviteCooldownByAgentRef.current.clear();
    transferPolicyByAgentRef.current.clear();
    senderDidCacheByAgentRef.current.clear();
    transferContextByAgentRef.current.clear();
    lastPeerRefreshAtByAgentRef.current.clear();
    lastGroupBootstrapAtByAgentRef.current.clear();
    lastPeerSessionSyncByAgentRef.current.clear();
    lastGroupSessionSyncByAgentRef.current.clear();
    deletedConversationDidsByAgentRef.current.clear();
    deletedGroupConversationIdsByAgentRef.current.clear();
    lastAutoOpenedDidByAgentRef.current.clear();
    lastConnectedLineKeyByAgentRef.current.clear();
    modeByAgentRef.current.clear();
    messageSeqByAgentRef.current.clear();
    refreshInFlightRef.current = false;
    if (eventRefreshTimerRef.current) {
      window.clearTimeout(eventRefreshTimerRef.current);
      eventRefreshTimerRef.current = null;
    }
    lastGhostScrubAtRef.current = 0;
    lastHydratedAgentRef.current = null;
    setRenderEpoch((v) => v + 1);
  }

  function extractInviteCodes(runtime: RuntimeSnapshot | null): { direct: string | null; group: string | null } {
    return {
      direct: runtime?.latest_invite_code?.trim() || null,
      group: runtime?.latest_group_invite_code?.trim() || null
    };
  }

  function findDidByName(runtime: RuntimeSnapshot | null, agent: string | null, name: string): string | null {
    const peers = runtime?.peers || [];
    const matches = peers.filter((p) => p.name.toLowerCase() === name.toLowerCase());
    if (matches.length === 1) return matches[0].did;
    if (matches.length > 1) {
      const onlineMatches = matches.filter((p) => isPeerOnlineStatus(p.status));
      if (onlineMatches.length === 1) return onlineMatches[0].did;
      const selectedDid = selectedPeerForAgent(agent);
      if (selectedDid && matches.some((m) => m.did === selectedDid)) {
        return selectedDid;
      }
      return null;
    }

    // Fallback: numeric selector (from /peers index).
    const numeric = Number(name);
    if (Number.isInteger(numeric) && numeric >= 1 && numeric <= peers.length) {
      const byIndex = peers[numeric - 1];
      if (byIndex?.did) return byIndex.did;
    }
    return null;
  }

  function peerByDid(runtime: RuntimeSnapshot | null, did: string | null): PeerSnapshot | null {
    if (!did) return null;
    const peers = runtime?.peers || [];
    return peers.find((p) => p.did === did) || null;
  }

  function visibleDidForPeer(peer: PeerSnapshot | null | undefined): string {
    return canonicalDidToContactDid(String(peer?.contact_did || peer?.did || "").trim());
  }

  function visibleDidForRuntimeDid(runtime: RuntimeSnapshot | null, did: string | null): string {
    const peer = peerByDid(runtime, did);
    const visible = visibleDidForPeer(peer);
    return visible || canonicalDidToContactDid(String(did || "").trim());
  }

  function findDidByConversationTitle(agent: string | null, sender: string): string | null {
    const map = conversationMapForAgent(agent);
    const matches = [...map.values()].filter(
      (c) => c.type === "dm" && c.did && c.title.toLowerCase() === sender.toLowerCase()
    );
    return matches.length === 1 ? (matches[0].did as string) : null;
  }

  function displayNameForDid(runtime: RuntimeSnapshot | null, did: string | null, fallback: string | null = null): string {
    const peer = peerByDid(runtime, did);
    if (peer?.name?.trim()) return cleanPeerName(peer.name.trim(), did || undefined);
    if (fallback && !isDid(fallback)) return cleanPeerName(fallback, did || undefined);
    const visibleDid = visibleDidForRuntimeDid(runtime, did);
    return visibleDid ? maskDidShort(visibleDid) : "unknown";
  }

  function memberDisplayLabel(
    runtime: RuntimeSnapshot | null,
    did: string,
    preferredName: string | null | undefined
  ): string {
    const preferred = preferredName?.trim() || "";
    if (preferred && !isDid(preferred)) {
      return cleanPeerName(preferred, did);
    }
    const peer = peerByDid(runtime, did);
    if (peer?.name?.trim()) {
      return cleanPeerName(peer.name.trim(), did);
    }
    return maskDidShort(visibleDidForRuntimeDid(runtime, did));
  }

  function resolveSenderDid(runtime: RuntimeSnapshot | null, agent: string | null, sender: string): string | null {
    if (!sender) return null;
    if (isDid(sender)) return sender;
    const byName = findDidByName(runtime, agent, sender);
    if (byName) return byName;
    const byConversation = findDidByConversationTitle(agent, sender);
    if (byConversation) return byConversation;
    const cached = senderDidCache(agent).get(sender.toLowerCase());
    if (cached) return cached;
    const peers = runtime?.peers || [];
    if (peers.length === 1) return peers[0].did;
    const dms = [...conversationMapForAgent(agent).values()].filter((c) => c.type === "dm" && c.did);
    if (dms.length === 1) return dms[0].did;
    const activeConv = getActiveConversation(agent);
    if (activeConv?.type === "dm" && activeConv.did && peers.length <= 1) return activeConv.did;
    return null;
  }

  function appendTransferTimelineMessage(
    agent: string | null,
    runtime: RuntimeSnapshot,
    map: Map<string, Conversation>,
    did: string | null,
    direction: MessageDirection,
    text: string,
    tsMs?: number
  ): void {
    if (!did || !text.trim()) return;
    if (isConversationDeleted(agent, did)) return;
    const title = displayNameForDid(runtime, did, did);
    const key = `dm:${did}`;
    ensureConversation(map, key, "dm", title, did);
    appendConversationMessage(agent, map, key, {
      direction,
      sender: direction === "out" ? "you" : "system",
      text,
      isTransfer: true,
      tsMs
    });
  }

  function upsertTransferProgressMessage(
    agent: string | null,
    runtime: RuntimeSnapshot | null,
    map: Map<string, Conversation>,
    did: string,
    direction: MessageDirection,
    transferKey: string,
    text: string,
    tsMs?: number
  ): void {
    if (!text.trim() || isConversationDeleted(agent, did)) return;
    const title = displayNameForDid(runtime, did, did);
    const key = `dm:${did}`;
    upsertTransferProgressMessageForConversation(
      agent,
      map,
      key,
      "dm",
      title,
      did,
      direction,
      transferKey,
      text,
      tsMs
    );
  }

  function upsertTransferProgressMessageForConversation(
    agent: string | null,
    map: Map<string, Conversation>,
    key: string,
    type: ConversationType,
    title: string,
    did: string | null,
    direction: MessageDirection,
    transferKey: string,
    text: string,
    tsMs?: number
  ): void {
    if (!text.trim()) return;
    if (type === "dm" && did && isConversationDeleted(agent, did)) return;
    ensureConversation(map, key, type, title, did);
    const conv = map.get(key);
    if (!conv) return;
    const existing = [...conv.messages]
      .reverse()
      .find((message) => message.isTransfer && message.transferKey === transferKey && message.transferStage === "progress");
    if (existing) {
      existing.text = text;
      existing.direction = direction;
      existing.sender = direction === "out" ? "you" : "system";
      if (typeof tsMs === "number" && Number.isFinite(tsMs)) {
        existing.tsMs = tsMs;
      }
      return;
    }
    appendConversationMessage(agent, map, key, {
      direction,
      sender: direction === "out" ? "you" : "system",
      text,
      isTransfer: true,
      transferKey,
      transferStage: "progress",
      tsMs
    });
  }

  function applyTransferEventToConversation(
    agent: string | null,
    runtime: RuntimeSnapshot | null,
    map: Map<string, Conversation>,
    payload: TransferRuntimeEvent
  ): void {
    const did = canonicalDidForTransferEvent(payload) || null;
    const visibleDid = visibleDidForTransferEvent(payload) || did;
    const groupId = payload.group_id?.trim() || null;
    const isGroupTransfer = !!groupId;
    if (!did && !groupId) return;
    if (isGroupTransfer && groupId) {
      const deletedAtMs = deletedGroupConversationAt(agent, groupId);
      if (
        shouldHideDeletedGroupConversation({
          deletedAtMs,
          groupStillPresent: mailboxGroups(runtime).some((group) => group.group_id === groupId),
          latestActivityTsMs: payload.ts_ms || 0
        })
      ) {
        return;
      }
      if (
        deletedAtMs &&
        !isGroupConversationActivityVisibleAfterDelete({
          deletedAtMs,
          activityTsMs: payload.ts_ms || 0
        })
      ) {
        return;
      }
      if (deletedAtMs) {
        clearGroupConversationDeleted(agent, groupId);
      }
    }
    const conversationType: ConversationType = isGroupTransfer ? "group" : "dm";
    const title = isGroupTransfer
      ? payload.group_name?.trim() || groupId || "Mailbox Group"
      : displayNameForDid(runtime, did, payload.peer_name || visibleDid);
    const conversationKey = isGroupTransfer ? groupConversationKey(groupId as string) : `dm:${did}`;
    const conversationDid = isGroupTransfer ? null : did;
    ensureConversation(map, conversationKey, conversationType, title, conversationDid);

    const fileLabel = transferEventFileLabel(payload.filename);
    const fileSuffix = fileLabel ? ` • ${fileLabel}` : "";
    const reasonSuffix = payload.reason ? ` (${payload.reason})` : "";
    const transferKey = isGroupTransfer
      ? payload.session_id?.trim() || `group:${groupId}:${payload.event}:${fileLabel || "file"}`
      : transferEventKey(payload, did as string);

    if (payload.event === "incoming_progress" || payload.event === "outgoing_progress") {
      const progressText = formatTransferEventProgress(payload);
      if (!progressText) return;
      upsertTransferProgressMessageForConversation(
        agent,
        map,
        conversationKey,
        conversationType,
        title,
        conversationDid,
        payload.event === "outgoing_progress" ? "out" : "in",
        transferKey,
        `${payload.event === "outgoing_progress" ? "Sending" : "Receiving"} • ${progressText}${fileSuffix}`,
        payload.ts_ms || undefined
      );
      return;
    }

    let direction: MessageDirection = "in";
    let text = "";
    switch (payload.event) {
      case "outgoing_packing":
        direction = "out";
        text = `Packing file for transfer${fileSuffix}`;
        break;
      case "outgoing_preparing":
        direction = "out";
        text = `Preparing secure transfer${fileSuffix}`;
        break;
      case "outgoing_pending":
        direction = "out";
        text = `Waiting for receiver approval${fileSuffix}`;
        break;
      case "incoming_pending":
        direction = "in";
        text = `Incoming transfer request${fileSuffix}`;
        break;
      case "incoming_staged":
        direction = "in";
        text = `Secure handoff ready${fileSuffix}`;
        break;
      case "incoming_exported":
        direction = "in";
        text = `Secure handoff exported${fileSuffix}`;
        break;
      case "incoming_discarded":
        direction = "in";
        text = `Secure handoff discarded${fileSuffix}`;
        break;
      case "incoming_accepted":
        direction = "in";
        text = `Transfer accepted${fileSuffix}`;
        break;
      case "incoming_rejected":
        direction = "in";
        text = `Transfer rejected${fileSuffix}${reasonSuffix}`;
        break;
      case "incoming_complete":
      case "incoming_completed":
        direction = "in";
        text = `File received${fileSuffix}`;
        break;
      case "incoming_failed":
        direction = "in";
        text = `Incoming transfer failed${fileSuffix}${reasonSuffix}`;
        break;
      case "outgoing_accepted":
        direction = "out";
        text = `Transfer accepted by ${title}${fileSuffix}`;
        break;
      case "outgoing_rejected":
        direction = "out";
        text = `Transfer rejected by ${title}${fileSuffix}${reasonSuffix}`;
        break;
      case "outgoing_completed":
        direction = "out";
        text = `File sent${fileSuffix}`;
        break;
      default:
        return;
    }

    if (!isGroupTransfer && payload.event === "incoming_staged" && payload.handoff_id) {
      upsertGhostHandoffMessage(agent, did, title, {
        handoff_id: payload.handoff_id,
        peer_did: did,
        peer_contact_did: visibleDid,
        peer_canonical_did: did,
        peer_name: payload.peer_name || title,
        filename: fileLabel || "received-file",
        created_at_ms: payload.ts_ms || Date.now()
      });
      return;
    }

    if (
      !isGroupTransfer &&
      (payload.event === "incoming_exported" || payload.event === "incoming_discarded") &&
      payload.handoff_id
    ) {
      updateGhostHandoffMessageState(
        String(agent || payload.agent || ""),
        payload.handoff_id,
        payload.event === "incoming_exported" ? "exported" : "discarded",
        text
      );
      return;
    }

    appendConversationMessage(agent, map, conversationKey, {
      direction,
      sender: direction === "out" ? "you" : "system",
      text,
      isTransfer: true,
      transferKey,
      transferStage: payload.event,
      tsMs: payload.ts_ms || undefined
    });
  }

  function upsertGhostHandoffMessage(
    agent: string | null,
    did: string,
    title: string,
    handoff: GhostHandoffSnapshot
  ): void {
    if (isConversationDeleted(agent, did)) return;
    const map = conversationMapForAgent(agent);
    const key = `dm:${did}`;
    ensureConversation(map, key, "dm", title, did);
    const conv = map.get(key);
    if (!conv) return;
    const existing = conv.messages.find((message) => message.handoffId === handoff.handoff_id);
    if (existing) {
      existing.text = `Secure handoff ready • ${handoff.filename}`;
      existing.handoffState = "staged";
      existing.handoffFileName = handoff.filename;
      existing.isTransfer = true;
      existing.tsMs = handoff.created_at_ms;
      return;
    }
    appendConversationMessage(agent, map, key, {
      direction: "in",
      sender: "system",
      text: `Secure handoff ready • ${handoff.filename}`,
      isTransfer: true,
      handoffId: handoff.handoff_id,
      handoffState: "staged",
      handoffFileName: handoff.filename,
      tsMs: handoff.created_at_ms
    });
  }

  function updateGhostHandoffMessageState(
    agent: string,
    handoffId: string,
    nextState: GhostHandoffState,
    nextText: string
  ): void {
    const map = conversationMapForAgent(agent);
    for (const conv of map.values()) {
      const message = conv.messages.find((entry) => entry.handoffId === handoffId);
      if (!message) continue;
      message.text = nextText;
      message.handoffState = nextState;
      message.isTransfer = true;
      return;
    }
  }

  function syncGhostHandoffs(runtime: RuntimeSnapshot, agent: string | null): void {
    const map = conversationMapForAgent(agent);
    const stagedIds = new Set<string>();
    for (const handoff of runtime.ghost_handoffs || []) {
      stagedIds.add(handoff.handoff_id);
      const did = canonicalDidForGhostHandoff(handoff);
      const visibleDid = visibleDidForGhostHandoff(handoff) || did;
      const title = displayNameForDid(runtime, did, handoff.peer_name || visibleDid);
      upsertGhostHandoffMessage(agent, did, title, handoff);
    }

    for (const conv of map.values()) {
      conv.messages = conv.messages.filter((message) => {
        if (message.handoffState !== "staged" || !message.handoffId) return true;
        return stagedIds.has(message.handoffId);
      });
    }
  }

  function mailboxGroups(runtime: RuntimeSnapshot | null): MailboxGroupSnapshot[] {
    return runtime?.mailbox_groups || [];
  }

  function buildGroupConversationRenderState(
    runtime: RuntimeSnapshot,
    agent: string | null
  ): GroupConversationRenderState {
    const knownGroups = mailboxGroups(runtime);
    const knownGroupIds = new Set(knownGroups.map((group) => group.group_id));
    const activitiesByGroupId = new Map<string, Array<{ kind?: string | null; tsMs?: number | null }>>();

    const pushActivity = (groupId: string | null | undefined, kind: string | null | undefined, tsMs: number | null | undefined) => {
      const trimmedGroupId = String(groupId || "").trim();
      if (!trimmedGroupId) return;
      let activities = activitiesByGroupId.get(trimmedGroupId);
      if (!activities) {
        activities = [];
        activitiesByGroupId.set(trimmedGroupId, activities);
      }
      activities.push({ kind, tsMs });
    };

    for (const event of runtime.group_events || []) {
      pushActivity(event.group_id, event.kind, event.ts_ms);
    }
    for (const event of runtime.transfer_events || []) {
      pushActivity(event.group_id, event.event, event.ts_ms);
    }

    const deletedCutoffByGroupId = new Map<string, number>();
    const hiddenGroupIds = new Set<string>();
    for (const group of knownGroups) {
      const deletedAtMs = deletedGroupConversationAt(agent, group.group_id);
      if (!deletedAtMs) continue;
      const latestActivityTsMs = latestGroupConversationActivityTsMs(
        activitiesByGroupId.get(group.group_id) || []
      );
      if (
        shouldHideDeletedGroupConversation({
          deletedAtMs,
          groupStillPresent: true,
          latestActivityTsMs
        })
      ) {
        hiddenGroupIds.add(group.group_id);
        continue;
      }
      deletedCutoffByGroupId.set(group.group_id, deletedAtMs);
      clearGroupConversationDeleted(agent, group.group_id);
    }

    const removedGroupIds = new Set(
      (runtime.group_events || [])
        .filter(
          (event) =>
            !!event.group_id?.trim() &&
            isGroupConversationRemovalKind(event.kind) &&
            !knownGroupIds.has(event.group_id)
        )
        .map((event) => event.group_id)
    );

    return {
      deletedCutoffByGroupId,
      hiddenGroupIds,
      removedGroupIds
    };
  }

  function mailboxGroupLabel(group: MailboxGroupSnapshot | null | undefined): string {
    if (!group) return "Mailbox Group";
    return group.group_name?.trim() || group.group_id;
  }

  function mailboxGroupLockLabel(group: MailboxGroupSnapshot | null | undefined): string {
    return group?.join_locked ? "Locked" : "Unlocked";
  }

  function mailboxGroupLockPillClass(group: MailboxGroupSnapshot | null | undefined): string {
    return group?.join_locked ? "warn" : "subtle";
  }

  function mailboxGroupAnonymousSecurityState(
    group: MailboxGroupSnapshot | null | undefined
  ): "v2_secure" | "legacy" | null {
    if (!group?.anonymous_group) return null;
    return String(group.anonymous_security_state || "").trim().toLowerCase() === "v2_secure"
      ? "v2_secure"
      : "legacy";
  }

  function mailboxGroupAnonymousSecurityLabel(
    group: MailboxGroupSnapshot | null | undefined
  ): string | null {
    const state = mailboxGroupAnonymousSecurityState(group);
    if (!state) return null;
    return state === "v2_secure" ? "v2 secure" : "legacy";
  }

  function mailboxGroupAnonymousSecurityPillClass(
    group: MailboxGroupSnapshot | null | undefined
  ): string {
    return mailboxGroupAnonymousSecurityState(group) === "v2_secure" ? "subtle" : "warn";
  }

  function mergeRuntimeGroupEvent(
    runtimeValue: RuntimeSnapshot,
    event: GroupMailboxRuntimeEvent
  ): RuntimeSnapshot {
    const mailboxGroups = [...(runtimeValue.mailbox_groups || [])];
    const groupEvents = [...(runtimeValue.group_events || [])];
    if (!groupEvents.some((existing) => sameGroupRuntimeEvent(existing, event))) {
      groupEvents.push(event);
      while (groupEvents.length > 400) {
        groupEvents.shift();
      }
    }

    if (event.kind === "group_disbanded" || event.kind === "group_removed") {
      return {
        ...runtimeValue,
        mailbox_groups: mailboxGroups.filter((group) => group.group_id !== event.group_id),
        group_events: groupEvents
      };
    }

    const targetIndex = mailboxGroups.findIndex((group) => group.group_id === event.group_id);
    if (targetIndex < 0) {
      return {
        ...runtimeValue,
        group_events: groupEvents
      };
    }

    const target = mailboxGroups[targetIndex];
    const nextGroup: MailboxGroupSnapshot = {
      ...target
    };

    if (event.kind === "membership_notice" && event.member_id?.trim()) {
      const memberId = event.member_id.trim();
      if (!nextGroup.known_member_ids.includes(memberId)) {
        nextGroup.known_member_ids = [...nextGroup.known_member_ids, memberId].sort();
      }
    }

    if (
      event.kind === "mailbox_rotation" ||
      event.kind === "local_kick" ||
      event.kind === "mailbox_locked" ||
      event.kind === "mailbox_unlocked"
    ) {
      if (typeof event.mailbox_epoch === "number") {
        nextGroup.mailbox_epoch = event.mailbox_epoch;
      }
      if (event.kind === "mailbox_locked") {
        nextGroup.join_locked = true;
      } else if (event.kind === "mailbox_unlocked") {
        nextGroup.join_locked = false;
      }
      if (event.kicked_member_id?.trim()) {
        nextGroup.known_member_ids = nextGroup.known_member_ids.filter(
          (memberId) => memberId !== event.kicked_member_id?.trim()
        );
      }
    }

    mailboxGroups[targetIndex] = nextGroup;
    return {
      ...runtimeValue,
      mailbox_groups: mailboxGroups,
      group_events: groupEvents
    };
  }

  function mergeSnapshotGroupEvent(
    currentSnapshot: AppSnapshot | null,
    payload: NamedGroupMailboxRuntimeEvent
  ): AppSnapshot | null {
    if (!currentSnapshot?.runtime) return currentSnapshot;
    if (!payload.agent || currentSnapshot.active_agent !== payload.agent) {
      return currentSnapshot;
    }
    return {
      ...currentSnapshot,
      runtime: mergeRuntimeGroupEvent(currentSnapshot.runtime, payload.event)
    };
  }

  function selectedMailboxGroup(runtime: RuntimeSnapshot | null, agent: string | null): MailboxGroupSnapshot | null {
    const groups = mailboxGroups(runtime);
    const activeGroupId = groupIdFromConversationKey(activeConversationKeyForAgent(agent));
    if (activeGroupId) {
      const activeMatch = groups.find((group) => group.group_id === activeGroupId) || null;
      if (activeMatch) {
        setSelectedGroupForAgent(agent, activeMatch.group_id);
        return activeMatch;
      }
    }
    const selected = selectedGroupForAgent(agent);
    if (selected) {
      const match = groups.find((group) => group.group_id === selected) || null;
      if (match) return match;
    }
    if (!groups.length) {
      setSelectedGroupForAgent(agent, null);
      return null;
    }
    setSelectedGroupForAgent(agent, groups[0].group_id);
    return groups[0];
  }

  function rebuildMailboxGroupConversations(
    runtime: RuntimeSnapshot,
    agent: string | null,
    map: Map<string, Conversation>
  ): void {
    const knownGroups = mailboxGroups(runtime);
    const { deletedCutoffByGroupId, hiddenGroupIds, removedGroupIds } = buildGroupConversationRenderState(
      runtime,
      agent
    );

    for (const key of [...map.keys()]) {
      const groupId = groupIdFromConversationKey(key);
      if (groupId && (removedGroupIds.has(groupId) || hiddenGroupIds.has(groupId))) {
        map.delete(key);
      }
    }

    for (const key of [...map.keys()]) {
      if (groupIdFromConversationKey(key)) {
        map.delete(key);
      }
    }

    for (const group of knownGroups) {
      if (hiddenGroupIds.has(group.group_id)) continue;
      ensureConversation(map, groupConversationKey(group.group_id), "group", mailboxGroupLabel(group));
    }

    const groupEvents = (runtime.group_events || [])
      .slice(-300)
      .map((event, index) => ({ event, index }))
      .sort((a, b) => {
        const aTs = a.event.ts_ms || 0;
        const bTs = b.event.ts_ms || 0;
        if (aTs !== bTs) return aTs - bTs;
        return a.index - b.index;
      })
      .map(({ event }) => event);

    const groupTransferEvents = (runtime.transfer_events || [])
      .filter((event) => !!event.group_id?.trim())
      .map((event, index) => ({ event, index }))
      .sort((a, b) => {
        const aTs = a.event.ts_ms || 0;
        const bTs = b.event.ts_ms || 0;
        if (aTs !== bTs) return aTs - bTs;
        return a.index - b.index;
      })
      .map(({ event }) => event);

    const localOutgoing = localGroupOutgoingForAgent(agent);

    for (const entry of buildGroupConversationTimeline(groupEvents, groupTransferEvents, localOutgoing)) {
      if (entry.kind === "group_event") {
        const event = entry.groupEvent;
        if (removedGroupIds.has(event.group_id) || hiddenGroupIds.has(event.group_id)) {
          continue;
        }
        const deletedCutoff = deletedCutoffByGroupId.get(event.group_id) || null;
        if (
          deletedCutoff &&
          !isGroupConversationActivityVisibleAfterDelete({
            deletedAtMs: deletedCutoff,
            activityTsMs: event.ts_ms || 0
          })
        ) {
          continue;
        }
        const group = knownGroups.find((candidate) => candidate.group_id === event.group_id) || null;
        const groupLabel = resolveMailboxGroupConversationLabel(
          event.group_id,
          event.group_name,
          group
        );
        const key = groupConversationKey(event.group_id);
        const chatSenderLabel =
          event.member_display_name && event.sender_member_id
            ? `${event.member_display_name} (${event.sender_member_id})`
            : event.member_display_name || event.sender_member_id || "anonymous member";

        switch (event.kind) {
          case "chat":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: chatSenderLabel,
              text: event.message || "",
              tsMs: event.ts_ms || undefined
            });
            break;
          case "file_manifest":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: `${event.member_display_name || event.sender_member_id || "someone"} shared file${event.filename ? ` • ${event.filename}` : ""}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "file_offer_pending":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text:
                event.message ||
                `approval required${event.filename ? ` • ${event.filename}` : ""}${event.member_display_name || event.sender_member_id ? ` • from ${event.member_display_name || event.sender_member_id}` : ""}`,
              isTransfer: true,
              transferKey:
                event.manifest_id ||
                `group-offer:${event.group_id}:${event.sender_member_id || "member"}:${event.filename || "file"}`,
              transferStage: "group_offer_pending",
              tsMs: event.ts_ms || undefined
            });
            break;
          case "file_offer_accepted":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: event.message || `accepted${event.filename ? ` • ${event.filename}` : ""}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "file_offer_rejected":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: event.message || `rejected${event.filename ? ` • ${event.filename}` : ""}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "membership_notice":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: `member joined • ${event.member_display_name || event.member_id || "unknown member"}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "direct_handshake_offer":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: `direct trust offer from ${event.sender_member_id || "unknown member"}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "direct_handshake_offer_accepted":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: event.message || `direct trust accepted • ${event.sender_member_id || "unknown member"}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "direct_handshake_offer_rejected":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: event.message || `direct trust rejected • ${event.sender_member_id || "unknown member"}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "direct_handshake_offer_blocked":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: event.message || `direct trust blocked • ${event.sender_member_id || "unknown member"}`,
              tsMs: event.ts_ms || undefined
            });
            break;
          case "mailbox_rotation":
          case "local_kick":
            ensureConversation(map, key, "group", groupLabel);
            appendConversationMessage(agent, map, key, {
              direction: "in",
              sender: "system",
              text: `mailbox epoch ${event.mailbox_epoch || 0} • removed ${event.kicked_member_id || "member"}`,
              tsMs: event.ts_ms || undefined
            });
            break;
        }
        continue;
      }

      if (entry.kind === "transfer_event") {
        const payload = entry.transferEvent;
        const groupId = payload.group_id?.trim() || null;
        if (!groupId) continue;
        if (hiddenGroupIds.has(groupId) || removedGroupIds.has(groupId)) {
          continue;
        }
        const deletedCutoff = deletedCutoffByGroupId.get(groupId) || null;
        if (
          deletedCutoff &&
          !isGroupConversationActivityVisibleAfterDelete({
            deletedAtMs: deletedCutoff,
            activityTsMs: payload.ts_ms || 0
          })
        ) {
          continue;
        }
        applyTransferEventToConversation(agent, runtime, map, payload);
        continue;
      }

      const payload = entry.localOutgoing;
      if (hiddenGroupIds.has(payload.groupId) || removedGroupIds.has(payload.groupId)) {
        continue;
      }
      const group = knownGroups.find((candidate) => candidate.group_id === payload.groupId) || null;
      const key = groupConversationKey(payload.groupId);
      ensureConversation(
        map,
        key,
        "group",
        resolveMailboxGroupConversationLabel(payload.groupId, null, group)
      );
      appendConversationMessage(agent, map, key, {
        direction: "out",
        sender: "you",
        text: payload.text,
        isTransfer: !!payload.isTransfer,
        tsMs: payload.tsMs
      });
    }
  }

  function syncActiveConversation(agent: string | null, map: Map<string, Conversation>): void {
    const currentKey = activeConversationKeyForAgent(agent);
    if (currentKey && map.has(currentKey)) {
      const current = map.get(currentKey) || null;
      if (current?.type === "group") {
        setSelectedGroupForAgent(agent, groupIdFromConversationKey(current.key));
        setSelectedPeerForAgent(agent, null);
      } else if (current?.did) {
        setSelectedPeerForAgent(agent, current.did);
      }
      return;
    }

    const fallbackKey = defaultConversationKey([...map.values()]);
    setActiveConversationKey(agent, fallbackKey);
    if (!fallbackKey) {
      setSelectedGroupForAgent(agent, null);
      setSelectedPeerForAgent(agent, null);
      return;
    }

    const fallback = map.get(fallbackKey) || null;
    if (fallback?.type === "group") {
      setSelectedGroupForAgent(agent, groupIdFromConversationKey(fallback.key));
      setSelectedPeerForAgent(agent, null);
    } else if (fallback?.did) {
      setSelectedPeerForAgent(agent, fallback.did);
    }
  }

  function rebuildDirectMessageConversations(
    runtime: RuntimeSnapshot,
    agent: string | null,
    map: Map<string, Conversation>
  ): void {
    const timeline = buildDirectConversationTimeline(
      directMessageEvents(runtime),
      runtime.transfer_events || []
    );

    for (const entry of timeline) {
      if (entry.kind === "direct") {
        const event = entry.directEvent;
        const did = canonicalDidForDirectMessageEvent(event);
        if (!did) continue;
        if (isConversationDeleted(agent, did) && event.direction !== "incoming") continue;
        if (event.direction === "incoming" && isConversationDeleted(agent, did)) {
          clearConversationDeleted(agent, did);
        }

        const peerName = event.peer_name?.trim() || visibleDidForDirectMessageEvent(event) || did;
        senderDidCache(agent).set(peerName.toLowerCase(), did);
        const title = displayNameForDid(runtime, did, peerName);
        const key = `dm:${did}`;
        ensureConversation(map, key, "dm", title, did);
        appendConversationMessage(agent, map, key, {
          direction: event.direction === "outgoing" ? "out" : "in",
          sender: event.direction === "outgoing" ? "you" : title,
          text: event.message,
          tsMs: event.ts_ms || undefined
        });
        continue;
      }

      applyTransferEventToConversation(agent, runtime, map, entry.transferEvent);
    }
  }

  function syncGhostConversations(runtime: RuntimeSnapshot, agent: string | null): void {
    const map = conversationMapForAgent(agent);
    rebuildMailboxGroupConversations(runtime, agent, map);
    selectedMailboxGroup(runtime, agent);
    syncPeerConversationMetadata(runtime, agent, map);
    rebuildDirectMessageConversations(runtime, agent, map);
    pruneImplicitEmptyDmConversations(agent, map);

    syncActiveConversation(agent, map);

    syncGhostHandoffs(runtime, agent);
  }

  function applyGhostTransferEvent(payload: TransferRuntimeEvent): void {
    const ctx = transferContextForAgent(payload.agent);
    applyTransferEventToTransferContext(ctx, payload);
    if (!isGhostAgent(payload.agent)) {
      forceRender();
      return;
    }

    const runtimeValue = runtimeForAgent(payload.agent);
    const map = conversationMapForAgent(payload.agent);
    applyTransferEventToConversation(payload.agent, runtimeValue, map, payload);
    forceRender();
  }

  function rebuildConversations(runtime: RuntimeSnapshot, agent: string | null): void {
    const previousMap = conversationMapForAgent(agent);
    const map = new Map<string, Conversation>();
    rebuildMailboxGroupConversations(runtime, agent, map);
    selectedMailboxGroup(runtime, agent);
    syncPeerConversationMetadata(runtime, agent, map);
    rebuildDirectMessageConversations(runtime, agent, map);
    mergePendingDirectMessages(previousMap, map);

    for (const [key, prev] of previousMap.entries()) {
      if (groupIdFromConversationKey(key)) continue;
      if (map.has(key)) continue;
      if (prev.type !== "dm" || !prev.did) continue;
      if (isConversationDeleted(agent, prev.did)) continue;
      if (!prev.messages.length && !prev.isExplicit) continue;
      map.set(key, {
        key: prev.key,
        type: "dm",
        title: prev.title,
        did: prev.did,
                messages: [...prev.messages],
                isExplicit: prev.isExplicit
              });
    }

    syncPeerConversationMetadata(runtime, agent, map);
    pruneImplicitEmptyDmConversations(agent, map);
    conversationStoreRef.current.set(getAgentKey(agent), map);
    syncActiveConversation(agent, map);
  }

  function parseTransferFeed(runtime: RuntimeSnapshot | null): TransferFeedItem[] {
    if (runtime?.mode === "ghost") return [];
    const conv = getActiveConversation(activeAgentName);
    if (!conv || conv.type !== "dm" || !conv.did) return [];

    const activeDid = conv.did;
    const ctx = transferContextForAgent(activeAgentName);
    const onlineDids = new Set((runtime?.peers || []).map((p) => p.did));
    if (!onlineDids.has(activeDid)) {
      ctx.outgoingDid = null;
      ctx.outgoingSession = null;
      ctx.lastPackedDid = null;
      ctx.localStage = null;
      ctx.sessionDid = Object.create(null);
      return [];
    }

    const transferEvents = (runtime.transfer_events || [])
      .filter((event) => canonicalDidForTransferEvent(event) === activeDid)
      .slice(-80);
    const latestOutgoing = lastItem(
      [...transferEvents]
        .filter((event) => event.direction === "outgoing" || event.direction === "out")
        .sort((a, b) => (a.ts_ms || 0) - (b.ts_ms || 0))
    );
    const latestIncoming = lastItem(
      [...transferEvents]
        .filter((event) => event.direction === "incoming" || event.direction === "in")
        .sort((a, b) => (a.ts_ms || 0) - (b.ts_ms || 0))
    );
    const items: TransferFeedItem[] = [];

    reconcileTransferContextForPeer(ctx, activeDid, latestOutgoing);

    if (!latestOutgoing && ctx.localStage === "packing" && ctx.outgoingDid === activeDid) {
      items.push({ kind: "outgoing", text: "Packing file for transfer..." });
    }

    if (!latestOutgoing && ctx.localStage === "preparing" && ctx.outgoingDid === activeDid) {
      items.push({ kind: "outgoing", text: "Preparing secure transfer..." });
    }

    if (latestIncoming) {
      const incomingFile = transferEventFileLabel(latestIncoming.filename);
      const incomingSuffix = incomingFile ? ` • ${incomingFile}` : "";
      const incomingProgress = formatTransferEventProgress(latestIncoming);
      switch (latestIncoming.event) {
        case "incoming_pending":
          items.push({ kind: "incoming", text: `Incoming transfer request from ${conv.title}${incomingSuffix}` });
          break;
        case "incoming_accepted":
          items.push({ kind: "incoming", text: `Incoming transfer started${incomingSuffix}` });
          break;
        case "incoming_progress":
          items.push({
            kind: "incoming",
            text: incomingProgress ? `Receiving • ${incomingProgress}${incomingSuffix}` : `Receiving${incomingSuffix}`
          });
          break;
        case "incoming_rejected":
        case "incoming_failed":
          items.push({ kind: "error", text: `Incoming transfer failed${incomingSuffix}` });
          break;
        default:
          break;
      }
    }

    if (latestOutgoing && canonicalDidForTransferEvent(latestOutgoing) === activeDid) {
      const outgoingFile = transferEventFileLabel(latestOutgoing.filename);
      const outgoingSuffix = outgoingFile ? ` • ${outgoingFile}` : "";
      const outgoingProgress = formatTransferEventProgress(latestOutgoing);
      switch (latestOutgoing.event) {
        case "outgoing_packing":
          items.push({ kind: "outgoing", text: `Packing file for transfer${outgoingSuffix}` });
          break;
        case "outgoing_preparing":
          items.push({ kind: "outgoing", text: `Preparing secure transfer${outgoingSuffix}` });
          break;
        case "outgoing_pending":
          items.push({ kind: "outgoing", text: `Waiting for receiver approval${outgoingSuffix}` });
          break;
        case "outgoing_accepted":
          items.push({ kind: "outgoing", text: `Receiver approved, transfer started${outgoingSuffix}` });
          break;
        case "outgoing_progress":
          items.push({
            kind: "outgoing",
            text: outgoingProgress ? `Sending • ${outgoingProgress}${outgoingSuffix}` : `Sending${outgoingSuffix}`
          });
          break;
        case "outgoing_rejected":
          items.push({ kind: "error", text: `Outgoing transfer rejected/failed${outgoingSuffix}` });
          break;
        default:
          break;
      }
    }

    return items;
  }

  async function invokeOrThrow<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
    return invoke<T>(command, args);
  }

  async function refreshAiProviderCatalog(): Promise<void> {
    setOllamaCatalogLoading(true);
    try {
      const next = await invokeOrThrow<AiProviderCatalog>("list_ai_provider_catalog");
      setOllamaCatalog(next);
      if (aiProvider === "ollama" && !aiModel.trim() && next.ollama_models.length > 0) {
        setAiModel(next.ollama_models[0].id);
      }
    } finally {
      setOllamaCatalogLoading(false);
    }
  }

  async function refreshAiProviderSecretStatus(provider: AiProviderKind = aiProvider): Promise<void> {
    if (!providerNeedsApiKey(provider)) {
      setAiProviderSecretStatus(null);
      return;
    }
    setAiProviderSecretLoading(true);
    try {
      const status = await invokeOrThrow<AiProviderSecretStatus>("get_ai_provider_secret_status", {
        provider
      });
      setAiProviderSecretStatus(status);
      setAiProviderSecretStatusCache((current) => ({ ...current, [provider]: status }));
    } finally {
      setAiProviderSecretLoading(false);
    }
  }

  async function saveAiProviderSecret(): Promise<void> {
    if (!providerNeedsApiKey(aiProvider)) {
      return;
    }
    const secret = aiProviderApiKeyInput.trim();
    if (!secret) {
      throw new Error("API key is required");
    }
    setAiProviderSecretSaving(true);
    try {
      const status = await invokeOrThrow<AiProviderSecretStatus>("set_ai_provider_secret", {
        req: {
          provider: aiProvider,
          api_key: secret
        }
      });
      setAiProviderSecretStatus(status);
      setAiProviderSecretStatusCache((current) => ({ ...current, [aiProvider]: status }));
      setAiProviderApiKeyInput("");
      setUiFeedback(`${providerLabel(aiProvider)} API key saved to secure storage`, false);
    } finally {
      setAiProviderSecretSaving(false);
    }
  }

  async function deleteAiProviderSecret(): Promise<void> {
    if (!providerNeedsApiKey(aiProvider)) {
      return;
    }
    setAiProviderSecretSaving(true);
    try {
      const status = await invokeOrThrow<AiProviderSecretStatus>("delete_ai_provider_secret", {
        provider: aiProvider
      });
      setAiProviderSecretStatus(status);
      setAiProviderSecretStatusCache((current) => ({ ...current, [aiProvider]: status }));
      setAiProviderApiKeyInput("");
      setUiFeedback(`${providerLabel(aiProvider)} API key removed from secure storage`, false);
    } finally {
      setAiProviderSecretSaving(false);
    }
  }

  function resetAgentSkillEditor(): void {
    setSelectedAgentSkillId(null);
    setAgentSkillNameInput("");
    setAgentSkillMarkdownInput("");
  }

  function applyAgentSkillToEditor(skill: AgentSkillRecord | null): void {
    if (!skill) {
      resetAgentSkillEditor();
      return;
    }
    setSelectedAgentSkillId(skill.id);
    setAgentSkillNameInput(skill.name);
    setAgentSkillMarkdownInput(skill.markdown);
  }

  async function refreshAgentSkills(
    targetAgentName = agentType === "ai" ? agentName.trim() : "",
    options?: { preferredSkillId?: string | null }
  ): Promise<void> {
    const trimmedAgentName = targetAgentName.trim();
    if (!trimmedAgentName || agentType !== "ai") {
      setAgentSkills([]);
      resetAgentSkillEditor();
      return;
    }
    setAgentSkillsLoading(true);
    try {
      const nextSkills = await invokeOrThrow<AgentSkillRecord[]>("list_agent_skills", {
        agentName: trimmedAgentName
      });
      setAgentSkills(nextSkills);
      const preferredId = options?.preferredSkillId ?? selectedAgentSkillId;
      if (preferredId) {
        const matched = nextSkills.find((skill) => skill.id === preferredId) || null;
        if (matched) {
          applyAgentSkillToEditor(matched);
          return;
        }
      }
      if (nextSkills.length > 0) {
        applyAgentSkillToEditor(nextSkills[0]);
      } else {
        resetAgentSkillEditor();
      }
    } finally {
      setAgentSkillsLoading(false);
    }
  }

  async function saveAgentSkill(): Promise<void> {
    const trimmedAgentName = agentName.trim();
    const trimmedSkillName = agentSkillNameInput.trim();
    const trimmedMarkdown = agentSkillMarkdownInput.trim();
    if (agentType !== "ai") {
      throw new Error("Skills are only available for AI agents");
    }
    if (!trimmedAgentName) {
      throw new Error("Set an AI agent name before saving skills");
    }
    if (!trimmedSkillName) {
      throw new Error("Skill name is required");
    }
    if (!trimmedMarkdown) {
      throw new Error("Skill markdown is required");
    }
    setAgentSkillSaving(true);
    try {
      const saved = await invokeOrThrow<AgentSkillRecord>("save_agent_skill", {
        req: {
          agent_name: trimmedAgentName,
          skill_id: selectedAgentSkillId,
          name: trimmedSkillName,
          markdown: trimmedMarkdown
        }
      });
      await refreshAgentSkills(trimmedAgentName, { preferredSkillId: saved.id });
      setUiFeedback(`Skill '${saved.name}' saved for ${trimmedAgentName}`, false);
    } finally {
      setAgentSkillSaving(false);
    }
  }

  async function deleteAgentSkill(): Promise<void> {
    const trimmedAgentName = agentName.trim();
    const trimmedSkillId = selectedAgentSkillId?.trim() || "";
    if (agentType !== "ai") {
      throw new Error("Skills are only available for AI agents");
    }
    if (!trimmedAgentName || !trimmedSkillId) {
      return;
    }
    setAgentSkillDeletingId(trimmedSkillId);
    try {
      const nextSkills = await invokeOrThrow<AgentSkillRecord[]>("delete_agent_skill", {
        req: {
          agent_name: trimmedAgentName,
          skill_id: trimmedSkillId
        }
      });
      setAgentSkills(nextSkills);
      if (nextSkills.length > 0) {
        applyAgentSkillToEditor(nextSkills[0]);
      } else {
        resetAgentSkillEditor();
      }
      setUiFeedback(`Skill removed from ${trimmedAgentName}`, false);
    } finally {
      setAgentSkillDeletingId(null);
    }
  }

  function handleAiProviderSelect(nextProvider: AiProviderKind): void {
    setAiProvider(nextProvider);
    setAiProviderApiKeyInput("");
    if (nextProvider === "ollama") {
      setAiModel(ollamaCatalog?.ollama_models?.[0]?.id || "");
      return;
    }
    setAiModel("");
  }

  async function ensureBackendActiveAgent(agent: string | null): Promise<void> {
    const target = (agent || "").trim();
    if (!target) return;
    if ((snapshotRef.current?.active_agent || null) === target) return;
    const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: target });
    snapshotRef.current = next;
    setSnapshot(next);
    setActiveAgentName(next.active_agent || null);
  }

  function forceRender(): void {
    setRenderEpoch((v) => v + 1);
  }

  function currentRuntime(): RuntimeSnapshot | null {
    const snapshot = snapshotRef.current;
    if (!snapshot) return null;
    if ((snapshot.active_agent || null) !== activeAgentName) {
      return null;
    }
    return snapshot.runtime || null;
  }

  async function handleAgentTypeSwitch(nextType: AgentType): Promise<void> {
    setAgentType(nextType);

    const currentSnapshot = snapshotRef.current;
    const currentActiveCard =
      (currentSnapshot?.agents || []).find((agent) => agent.name === activeAgentName) || null;
    if (normalizeAgentType(currentActiveCard?.agent_type) === nextType) {
      return;
    }

    const matchingAgent =
      [...(currentSnapshot?.agents || [])]
        .filter((agent) => normalizeAgentType(agent.agent_type) === nextType)
        .sort((a, b) => a.name.localeCompare(b.name))[0] || null;

    if (!matchingAgent) {
      setActiveAgentName(null);
      forceRender();
      return;
    }

    setActiveAgentName(matchingAgent.name);
    forceRender();

    try {
      const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", {
        agentName: matchingAgent.name
      });
      await applySnapshot(next, true);
    } catch (error) {
      setUiFeedback(String(error), true);
    }
  }

  useEffect(() => {
    setListenPortInput(String(listenPort || 9090));
  }, [listenPort]);

  function syncAiAgentConversations(
    ownerAgent: string | null,
    map: Map<string, Conversation>
  ): void {
    const ownerName = String(ownerAgent || "").trim();
    const ownerCard =
      (snapshotRef.current?.agents || []).find((agent) => agent.name === ownerName) || null;
    const ownerIsAi = normalizeAgentType(ownerCard?.agent_type) === "ai";
    const controlDid = ownerIsAi && ownerName ? localAiDid(ownerName) : null;
    const controlKey = controlDid ? `dm:${controlDid}` : null;

    for (const [key, conv] of [...map.entries()]) {
      if (conv.type !== "dm" || !isLocalAiDid(conv.did)) continue;
      if (controlDid && conv.did === controlDid) continue;
      map.delete(key);
    }
    if (controlDid && controlKey) {
      ensureConversation(map, controlKey, "dm", aiControlConversationTitle(ownerName), controlDid, true);
      const conv = map.get(controlKey);
      if (conv) {
        conv.title = aiControlConversationTitle(ownerName);
        conv.isExplicit = true;
        conv.isPeerListed = true;
      }
      setSelectedPeerForAgent(ownerAgent, null);
      setSelectedGroupForAgent(ownerAgent, null);
      if (activeConversationKeyForAgent(ownerAgent) !== controlKey) {
        setActiveConversationKey(ownerAgent, controlKey);
      }
      return;
    }
    const activeKey = activeConversationKeyForAgent(ownerAgent);
    const activeConversation = activeKey ? map.get(activeKey) || null : null;
    if (activeConversation?.type === "dm" && isLocalAiDid(activeConversation.did)) {
      setActiveConversationKey(ownerAgent, defaultConversationKey([...map.values()]));
    }
    const selectedPeer = selectedPeerForAgent(ownerAgent);
    if (isLocalAiDid(selectedPeer)) {
      setSelectedPeerForAgent(ownerAgent, null);
    }
  }

  function applyAiThreadToConversation(
    ownerAgent: string | null,
    aiAgentName: string,
    thread: AiAgentThreadState
  ): void {
    const map = conversationMapForAgent(ownerAgent);
    const did = localAiDid(aiAgentName);
    const key = `dm:${did}`;
    ensureConversation(map, key, "dm", aiControlConversationTitle(aiAgentName), did, true);
    const conv = map.get(key);
    if (!conv) return;
    conv.title = aiControlConversationTitle(aiAgentName);
    conv.isExplicit = true;
    conv.isPeerListed = true;
    conv.messages = (thread.messages || []).map((entry, index) => ({
      direction: String(entry.role || "").trim().toLowerCase() === "assistant" ? "in" : "out",
      sender: String(entry.role || "").trim().toLowerCase() === "assistant" ? aiAgentName : "you",
      text: entry.content,
      seq: index + 1,
      tsMs: entry.ts_ms || Date.now()
    }));
    messageSeqByAgentRef.current.set(getAgentKey(ownerAgent), conv.messages.length);
  }

  async function hydrateAiConversation(
    ownerAgent: string | null,
    aiAgentName: string
  ): Promise<void> {
    const trimmedAiAgent = aiAgentName.trim();
    if (!trimmedAiAgent) return;
    const did = localAiDid(trimmedAiAgent);
    const key = `dm:${did}`;
    const requester =
      ownerAgent && ownerAgent.trim() && ownerAgent.trim() !== trimmedAiAgent
        ? ownerAgent.trim()
        : null;
    const thread = await invokeOrThrow<AiAgentThreadState>("load_ai_agent_thread", {
      req: {
        ai_agent: trimmedAiAgent,
        requester_agent: requester
      }
    });
    const currentConversation = conversationMapForAgent(ownerAgent).get(key) || null;
    const currentMessageCount = currentConversation?.messages.length || 0;
    const nextMessageCount = (thread.messages || []).length;
    if (
      ownerAgent &&
      ownerAgent.trim() === trimmedAiAgent &&
      currentMessageCount > nextMessageCount
    ) {
      return;
    }
    applyAiThreadToConversation(ownerAgent, trimmedAiAgent, thread);
    forceRender();
  }

  async function waitForAiConversationUpdate(
    ownerAgent: string | null,
    aiAgentName: string,
    previousCount: number,
    timeoutMs = 15000
  ): Promise<void> {
    const trimmedAiAgent = aiAgentName.trim();
    if (!trimmedAiAgent) return;
    const requester =
      ownerAgent && ownerAgent.trim() && ownerAgent.trim() !== trimmedAiAgent
        ? ownerAgent.trim()
        : null;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const thread = await invokeOrThrow<AiAgentThreadState>("load_ai_agent_thread", {
        req: {
          ai_agent: trimmedAiAgent,
          requester_agent: requester
        }
      });
      if ((thread.messages || []).length > previousCount) {
        applyAiThreadToConversation(ownerAgent, trimmedAiAgent, thread);
        forceRender();
        return;
      }
      await new Promise((resolve) => window.setTimeout(resolve, 250));
    }

    await hydrateAiConversation(ownerAgent, trimmedAiAgent);
  }

  function currentPollIntervalMs(): number {
    const runtimeValue = currentRuntime();
    return hasOutgoingTransferForUi(runtimeValue, activeAgentName) ? POLL_TRANSFER_MS : POLL_IDLE_MS;
  }

  async function applySnapshot(next: AppSnapshot, silent = false): Promise<void> {
    const snapshotAgent = next.active_agent || null;
    const snapshotAgentCard = next.agents.find((agent) => agent.name === snapshotAgent) || null;
    const snapshotAgentIsAi = normalizeAgentType(snapshotAgentCard?.agent_type) === "ai";

    snapshotRef.current = next;
    setSnapshot(next);
    setActiveAgentName(snapshotAgent);
    modeByAgentRef.current.clear();
    for (const agent of next.agents || []) {
      modeByAgentRef.current.set(agent.name, (agent.mode as LogMode) || "safe");
    }
    if (next.runtime && snapshotAgent) {
      modeByAgentRef.current.set(snapshotAgent, normalizeLogMode(next.runtime.mode));
    }

    if (snapshotAgent && snapshotAgent !== lastHydratedAgentRef.current) {
      const card = next.agents.find((a) => a.name === snapshotAgent) || null;
      if (card) {
        const nextAgentType = normalizeAgentType(card.agent_type);
        const normalizedProvider = String(card.ai_provider || "").trim().toLowerCase();
        const nextProvider = (AI_PROVIDER_OPTIONS.includes(normalizedProvider as AiProviderKind)
          ? (normalizedProvider as AiProviderKind)
          : "ollama");
        const nextTransport = (card.transport as TransportMode) || "internet";
        const nextMode = logModeForTransport(nextTransport, normalizeLogMode(card.mode));
        setAgentName(card.name);
        setAgentType(nextAgentType);
        setAiProvider(nextProvider);
        setAiModel(card.ai_model || "");
        setAiRole(card.ai_role || "general");
        setTransport(nextTransport);
        setLogMode(nextMode);
        setListenPort(card.listen_port || 9090);
        setConfigPath(card.config_path || ensureDerivedConfigPath(card.name, nextMode));
      }
      lastHydratedAgentRef.current = snapshotAgent;
    }

    const runtime = next.runtime;
    if (!runtime) {
      const map = conversationMapForAgent(snapshotAgent);
      syncAiAgentConversations(snapshotAgent, map);
      syncActiveConversation(snapshotAgent, map);
      const aiThreadTarget = snapshotAgentIsAi ? snapshotAgent : aiAgentNameFromDid(getActiveConversation(snapshotAgent)?.did);
      if (aiThreadTarget) {
        void hydrateAiConversation(snapshotAgent, aiThreadTarget).catch((err) =>
          setUiFeedback(String(err), true)
        );
      }
      setLatestInviteCode("");
      setLatestGroupInviteCode("");
      forceRender();
      return;
    }

    if (runtime.mode === "ghost") {
      syncGhostConversations(runtime, snapshotAgent);
    } else {
      rebuildConversations(runtime, snapshotAgent);
    }
    syncAiAgentConversations(snapshotAgent, conversationMapForAgent(snapshotAgent));
    syncActiveConversation(snapshotAgent, conversationMapForAgent(snapshotAgent));
    selectedMailboxGroup(runtime, snapshotAgent);

    const map = conversationMapForAgent(snapshotAgent);
    const agentKey = getAgentKey(snapshotAgent);
    const currentActiveKey = activeConversationKeyForAgent(snapshotAgent);
    {
      const dms = [...map.values()].filter((c) => c.type === "dm" && !!c.did);
      const latestConnectedEvent = lastItem(
        [...peerRuntimeEvents(runtime)].filter((event) => event.event === "connected")
      );
      const latestConnectedDid = latestConnectedEvent?.did || null;
      const latestConnectedLineKey = latestConnectedEvent
        ? `${latestConnectedEvent.did}:${latestConnectedEvent.ts_ms || 0}`
        : null;
      const lastAutoDid = lastAutoOpenedDidByAgentRef.current.get(agentKey) || null;
      const lastConnectedLineKey = lastConnectedLineKeyByAgentRef.current.get(agentKey) || null;
      let candidate: Conversation | null = null;
      const currentActiveConversation = map.get(currentActiveKey) || null;
      if (
        !snapshotAgentIsAi &&
        latestConnectedDid &&
        latestConnectedDid !== lastAutoDid &&
        latestConnectedLineKey &&
        latestConnectedLineKey !== lastConnectedLineKey
      ) {
        candidate = map.get(`dm:${latestConnectedDid}`) || null;
      } else if (currentActiveConversation?.type === "group" && dms.length === 1 && !lastAutoDid) {
        candidate = dms[0];
      }

      if (candidate?.did) {
        const peer = runtime.peers.find((p) => p.did === candidate?.did) || null;
        if (peer && !isPeerOnlineStatus(peer.status)) {
          // Do not auto-jump to offline conversation entries.
        } else {
          setActiveConversationKey(snapshotAgent, candidate.key);
          setSelectedPeerForAgent(snapshotAgent, candidate.did);
          lastAutoOpenedDidByAgentRef.current.set(agentKey, candidate.did);
          if (latestConnectedLineKey) {
            lastConnectedLineKeyByAgentRef.current.set(agentKey, latestConnectedLineKey);
          }
          focusConversationsCard();
          try {
            await invokeOrThrow<void>("runtime_set_selected_peer", { peer: candidate.did });
          } catch {
            // best-effort
          }
        }
      } else if (latestConnectedLineKey) {
        lastConnectedLineKeyByAgentRef.current.set(agentKey, latestConnectedLineKey);
      }
    }

    const codes = extractInviteCodes(runtime);
    setLatestInviteCode(codes.direct || "");
    setLatestGroupInviteCode(codes.group || "");

    const selectedPeer = selectedPeerForAgent(snapshotAgent);
    if (selectedPeer && !runtime.peers.some((p) => p.did === selectedPeer)) {
      setSelectedPeerForAgent(snapshotAgent, null);
    }

    if (runtime.mode === "ghost") {
      const now = Date.now();
      if (now - lastGhostScrubAtRef.current >= GHOST_SCRUB_INTERVAL_MS) {
        lastGhostScrubAtRef.current = now;
        void scrubBrowserResidue();
      }
    }

    const selectedAiAgent = snapshotAgentIsAi
      ? snapshotAgent
      : aiAgentNameFromDid(getActiveConversation(snapshotAgent)?.did);
    if (selectedAiAgent) {
      void hydrateAiConversation(snapshotAgent, selectedAiAgent).catch((err) =>
        setUiFeedback(String(err), true)
      );
    }

    forceRender();

    if (!silent) {
      setUiFeedback("", false);
    }
  }

  async function refreshSnapshot(silent = false): Promise<AppSnapshot> {
    let next = await invokeOrThrow<AppSnapshot>("runtime_snapshot");
    if (!next.active_agent && next.agents?.length) {
      next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", {
        agentName: next.agents[0].name
      });
    }
    await applySnapshot(next, silent);
    return next;
  }

  async function safeAction(fn: () => Promise<unknown> | unknown): Promise<void> {
    try {
      await fn();
      await refreshSnapshot(true);
    } catch (err) {
      setUiFeedback(String(err), true);
    }
  }

  async function runRuntimeAction(
    kind: RuntimeActionKind,
    fn: () => Promise<void>,
    pendingLabel: string
  ): Promise<void> {
    if (runtimeActionPending) return;
    setRuntimeActionPending(kind);
    setUiFeedback(pendingLabel, false);
    try {
      await fn();
      await refreshSnapshot(true);
    } catch (err) {
      setUiFeedback(String(err), true);
    } finally {
      setRuntimeActionPending(null);
    }
  }

  async function copyTextWithPolicy(value: string, label: string): Promise<void> {
    if (!value) {
      setUiFeedback(`${label} is empty`, true);
      return;
    }
    if (!allowClipboardCopy(currentRuntime()?.mode || (isGhostAgent(activeAgentName) ? "ghost" : ""))) {
      throw new Error("Ghost mode blocks clipboard copy");
    }
    await navigator.clipboard.writeText(value);
    setUiFeedback(`${label} copied`, false);
  }

  async function recoverInviteCodeFromSnapshot(
    kind: "direct" | "group",
    previousRevision: number,
    _previousCode: string,
    timeoutMs?: number
  ): Promise<string | null> {
    const deadline =
      Date.now() + (timeoutMs ?? (kind === "direct" ? 15000 : 25000));

    while (Date.now() < deadline) {
      const next = await invokeOrThrow<AppSnapshot>("runtime_snapshot");
      snapshotRef.current = next;
      setSnapshot(next);
      setActiveAgentName(next.active_agent || null);

      const runtimeValue = next.runtime || null;
      const revision =
        kind === "direct"
          ? Number(runtimeValue?.latest_invite_revision || 0)
          : Number(runtimeValue?.latest_group_invite_revision || 0);
      const stateCode = (
        kind === "direct"
          ? runtimeValue?.latest_invite_code
          : runtimeValue?.latest_group_invite_code
      )?.trim() || "";

      if (revision > previousRevision && stateCode) {
        return stateCode;
      }

      await new Promise((resolve) => window.setTimeout(resolve, 120));
    }

    return null;
  }

  function inviteDetectErrorMessage(kind: "direct" | "group"): string {
    return kind === "group" ? "New group invite not detected yet" : "New invite not detected yet";
  }

  function isInviteDetectError(error: unknown, kind: "direct" | "group"): boolean {
    const message = error instanceof Error ? error.message : String(error || "");
    return message.includes(inviteDetectErrorMessage(kind));
  }

  async function requestInviteCode(
    kind: "direct" | "group",
    command: string,
    args: Record<string, unknown>,
    previousRevision: number,
    previousCode: string
  ): Promise<string> {
    inviteActionInFlightRef.current = true;
    try {
      try {
        const code = (await invokeOrThrow<string>(command, args)).trim();
        if (code) return code;
      } catch (error) {
        if (!isInviteDetectError(error, kind)) {
          throw error;
        }
      }

      const recovered = await recoverInviteCodeFromSnapshot(
        kind,
        previousRevision,
        previousCode,
        kind === "direct" ? 2500 : 4000
      );
      if (recovered) {
        return recovered;
      }
      throw new Error(inviteDetectErrorMessage(kind));
    } finally {
      inviteActionInFlightRef.current = false;
    }
  }

  async function generateInvite(kind: "direct" | "group"): Promise<void> {
    const isGroup = kind === "group";
    const trimmedGroupName = groupInviteName.trim();
    if (isGroup && !trimmedGroupName) {
      throw new Error("Group name is required");
    }
    await ensureBackendActiveAgent(activeAgentName);
    const runtimeValue = currentRuntime();
    const previousRevision = isGroup
      ? Number(runtimeValue?.latest_group_invite_revision || 0)
      : Number(runtimeValue?.latest_invite_revision || 0);
    const previousCode = isGroup
      ? runtimeValue?.latest_group_invite_code?.trim() || ""
      : runtimeValue?.latest_invite_code?.trim() || "";
    if (isGroup) {
      setInviteHubSection("group");
      const code = await requestInviteCode(
        "group",
        "runtime_invite_group",
        { groupName: trimmedGroupName },
        previousRevision,
        previousCode
      );
      setLatestGroupInviteCode(code);
      setSelectedInviteGroupId(null);
      setLatestGroupInviteContext({ groupId: null, groupName: trimmedGroupName });
      setGroupInviteName("");
      await refreshSnapshot(true);
      setUiFeedback("New group invite generated", false);
      return;
    }
    setInviteHubSection("direct");
    const code = await requestInviteCode(
      "direct",
      "runtime_invite",
      {},
      previousRevision,
      previousCode
    );
    setLatestInviteCode(code);
    setUiFeedback("New invite generated", false);
  }

  function openMailboxGroupConversation(group: MailboxGroupSnapshot): void {
    forceScrollToBottomRef.current = true;
    clearGroupConversationDeleted(activeAgentName, group.group_id);
    setSelectedGroupForAgent(activeAgentName, group.group_id);
    setSelectedPeerForAgent(activeAgentName, null);
    setActiveConversationKey(activeAgentName, groupConversationKey(group.group_id));
    forceRender();
    focusConversationsCard();
  }

  function deleteConversation(agent: string | null, key: string): void {
    if (!key) return;
    if (groupIdFromConversationKey(key)) {
      deleteGroupConversation(agent, key);
      return;
    }
    const map = conversationMapForAgent(agent);
    const conv = map.get(key);
    if (!conv) return;
    const did = conv.did || null;
    const deletedKeys = did
      ? [...map.entries()]
          .filter(([candidateKey, candidate]) =>
            candidateKey === key || (candidate.type === "dm" && candidate.did === did)
          )
          .map(([candidateKey]) => candidateKey)
      : [key];
    for (const deletedKey of deletedKeys) {
      map.delete(deletedKey);
    }

    if (did) {
      markConversationDeleted(agent, did);
      const cache = senderDidCache(agent);
      for (const [sender, cachedDid] of [...cache.entries()]) {
        if (cachedDid === did) cache.delete(sender);
      }
      if (selectedPeerForAgent(agent) === did) {
        setSelectedPeerForAgent(agent, null);
      }
      const tx = transferContextForAgent(agent);
      if (tx.outgoingDid === did) {
        tx.outgoingDid = null;
        tx.outgoingSession = null;
        tx.lastPackedDid = null;
        tx.localStage = null;
        tx.sessionDid = Object.create(null);
      }
    }

    if (deletedKeys.includes(activeConversationKeyForAgent(agent))) {
      setActiveConversationKey(agent, defaultConversationKey([...conversationMapForAgent(agent).values()]));
    }

    forceRender();
  }

  function deleteGroupConversation(agent: string | null, key: string): void {
    const groupId = groupIdFromConversationKey(key);
    if (!key || !groupId) return;
    removeGroupConversationFromUi(agent, groupId, { markDeleted: true });

    forceRender();
  }

  function removeGroupConversationFromUi(
    agent: string | null,
    groupId: string,
    options: { clearInviteState?: boolean; markDeleted?: boolean } = {}
  ): void {
    const trimmedGroupId = groupId.trim();
    if (!trimmedGroupId) return;
    const key = groupConversationKey(trimmedGroupId);
    const map = conversationMapForAgent(agent);
    map.delete(key);
    if (options.markDeleted !== false) {
      markGroupConversationDeleted(agent, trimmedGroupId);
    } else {
      clearGroupConversationDeleted(agent, trimmedGroupId);
    }

    const localOutgoing = localGroupOutgoingForAgent(agent);
    for (let index = localOutgoing.length - 1; index >= 0; index -= 1) {
      if (localOutgoing[index]?.groupId === trimmedGroupId) {
        localOutgoing.splice(index, 1);
      }
    }

    if (selectedGroupForAgent(agent) === trimmedGroupId) {
      setSelectedGroupForAgent(agent, null);
    }
    if (activeConversationKeyForAgent(agent) === key) {
      syncActiveConversation(agent, map);
    }
    if (options.clearInviteState) {
      if (selectedInviteGroupId === trimmedGroupId) {
        setSelectedInviteGroupId(null);
      }
      if (latestGroupInviteContext?.groupId === trimmedGroupId) {
        setLatestGroupInviteContext(null);
        setLatestGroupInviteCode("");
      }
    }
  }

  function stripMailboxGroupFromSnapshot(next: AppSnapshot, groupId: string): AppSnapshot {
    const trimmedGroupId = groupId.trim();
    if (!trimmedGroupId || !next.runtime) return next;
    return {
      ...next,
      runtime: {
        ...next.runtime,
        mailbox_groups: (next.runtime.mailbox_groups || []).filter((group) => group.group_id !== trimmedGroupId),
        group_events: (next.runtime.group_events || []).filter((event) => event.group_id !== trimmedGroupId)
      }
    };
  }

  async function removeMailboxGroupConversation(
    agent: string | null,
    groupId: string,
    action: "leave" | "disband",
    label: string
  ): Promise<void> {
    const trimmedGroupId = groupId.trim();
    if (!trimmedGroupId) return;
    await ensureBackendActiveAgent(agent);
    if (action === "disband") {
      await invokeOrThrow<void>("runtime_disband_group", { groupId: trimmedGroupId });
    } else {
      await invokeOrThrow<void>("runtime_leave_group", { groupId: trimmedGroupId });
    }
    removeGroupConversationFromUi(agent, trimmedGroupId, {
      clearInviteState: true,
      markDeleted: true
    });
    const currentSnapshot = snapshotRef.current;
    if (currentSnapshot?.runtime) {
      await applySnapshot(stripMailboxGroupFromSnapshot(currentSnapshot, trimmedGroupId), true);
    }
    const refreshed = await invokeOrThrow<AppSnapshot>("runtime_snapshot");
    await applySnapshot(stripMailboxGroupFromSnapshot(refreshed, trimmedGroupId), true);
    setUiFeedback(
      action === "disband"
        ? `Deleted & disbanded mailbox group '${label}'`
        : `Left and deleted chat for mailbox group '${label}'`,
      false
    );
  }

  function clearAgentUiState(agent: string | null): void {
    const key = getAgentKey(agent);
    conversationStoreRef.current.delete(key);
    activeConversationByAgentRef.current.delete(key);
    selectedPeerByAgentRef.current.delete(key);
    selectedGroupByAgentRef.current.delete(key);
    senderDidCacheByAgentRef.current.delete(key);
    transferPolicyByAgentRef.current.delete(key);
    transferContextByAgentRef.current.delete(key);
    lastPeerRefreshAtByAgentRef.current.delete(key);
    lastGroupBootstrapAtByAgentRef.current.delete(key);
    lastPeerSessionSyncByAgentRef.current.delete(key);
    lastGroupSessionSyncByAgentRef.current.delete(key);
    deletedConversationDidsByAgentRef.current.delete(key);
    deletedGroupConversationIdsByAgentRef.current.delete(key);
    lastAutoOpenedDidByAgentRef.current.delete(key);
    lastConnectedLineKeyByAgentRef.current.delete(key);
    modeByAgentRef.current.delete(String(agent || ""));
    if (activeAgentName === agent) {
      setActiveAgentName(null);
      setLatestInviteCode("");
      setLatestGroupInviteCode("");
      setLatestGroupInviteContext(null);
      setInviteHubSection("direct");
      setSelectedInviteGroupId(null);
    }
    forceRender();
  }

  function clearAllAgentUiState(): void {
    clearSensitiveUiMemory();
    setSnapshot(null);
    snapshotRef.current = null;
    setActiveAgentName(null);
  }

  async function createAgent(): Promise<void> {
    const nextLogMode = logModeForTransport(transport, logMode);
    const targetName = agentName.trim();
    const nextListenPort = resolveListenPort(listenPortInput, listenPort || 9090);
    if (!targetName) throw new Error("Agent name is required");
    if (nextLogMode === "ghost") {
      throw new Error("Ghost mode does not create persistent config agents");
    }
    await invokeOrThrow<AppSnapshot>("agent_init", {
      req: {
        name: targetName,
        transport,
        log_mode: nextLogMode,
        listen_port: nextListenPort,
        passphrase,
        agent_type: "human",
        ai_provider: null,
        ai_model: null,
        ai_role: null,
        ai_access_mode: null
      }
    });
    const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: targetName });
    await applySnapshot(next, true);
    setUiFeedback(`Agent '${targetName}' initialized`, false);
  }

  async function ensureHumanProfile(): Promise<void> {
    const targetName = agentName.trim();
    if (!targetName) throw new Error("Agent name is required");
    const nextLogMode = logModeForTransport(transport, logMode);
    const nextListenPort = resolveListenPort(listenPortInput, listenPort || 9090);
    if (nextLogMode === "ghost") {
      return;
    }

    const existingHumanProfile =
      (snapshotRef.current?.agents || []).find(
        (agent) => agent.name === targetName && normalizeAgentType(agent.agent_type) === "human"
      ) || null;

    if (existingHumanProfile?.config_present) {
      const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: targetName });
      await applySnapshot(next, true);
      setListenPort(nextListenPort);
      return;
    }

    await invokeOrThrow<AppSnapshot>("agent_init", {
      req: {
        name: targetName,
        transport,
        log_mode: nextLogMode,
        listen_port: nextListenPort,
        passphrase,
        agent_type: "human",
        ai_provider: null,
        ai_model: null,
        ai_role: null,
        ai_access_mode: null
      }
    });
    const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: targetName });
    await applySnapshot(next, true);
    setListenPort(nextListenPort);
  }

  async function ensureAiProfile(): Promise<void> {
    const targetName = agentName.trim();
    if (!targetName) throw new Error("AI agent name is required");
    const nextLogMode = logModeForTransport(transport, logMode);
    const nextListenPort = resolveListenPort(listenPortInput, listenPort || 9090);

    await invokeOrThrow<AppSnapshot>("agent_init", {
      req: {
        name: targetName,
        transport,
        log_mode: nextLogMode,
        listen_port: nextListenPort,
        passphrase: "",
        agent_type: "ai",
        ai_provider: aiProvider,
        ai_model: aiModel.trim() || null,
        ai_role: aiRole,
        ai_access_mode: "full_access"
      }
    });
    const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: targetName });
    await applySnapshot(next, true);
    setListenPort(nextListenPort);
    setUiFeedback(
      `AI agent '${targetName}' saved (${providerLabel(aiProvider)}${aiModel.trim() ? ` • ${aiModel.trim()}` : ""} • ${transportLabel(transport)} • ${nextLogMode} • :${nextListenPort})`,
      false
    );
  }

  async function openAiConversation(): Promise<void> {
    const targetName = agentName.trim();
    if (!targetName) throw new Error("AI agent name is required");
    await ensureAiProfile();

    const matchingProfile = ((snapshotRef.current?.agents || []).find(
      (agent) => normalizeAgentType(agent.agent_type) === "ai" && agent.name === targetName
    ) ||
      null);

    forceScrollToBottomRef.current = true;
    await ensureBackendActiveAgent(targetName);
    const did = localAiDid(targetName);
    const key = `dm:${did}`;
    const map = conversationMapForAgent(targetName);
    ensureConversation(map, key, "dm", `AI • ${targetName}`, did, true);
    setSelectedPeerForAgent(targetName, null);
    setSelectedGroupForAgent(targetName, null);
    setActiveConversationKey(targetName, key);
    await hydrateAiConversation(targetName, targetName);
    forceRender();
    focusConversationsCard();

    const provider = String(matchingProfile?.ai_provider || aiProvider).trim().toLowerCase();
    if (provider !== "ollama") {
      setUiFeedback(
        `${providerLabel(provider)} profile '${targetName}' selected. Desktop embedded chat currently returns live replies only for Ollama.`,
        false
      );
      return;
    }
    setUiFeedback(`AI agent '${targetName}' ready in Conversations`, false);
  }

  async function startRuntime(): Promise<void> {
    if (agentType === "ai") {
      const nextLogMode = logModeForTransport(transport, logMode);
      const nextListenPort = resolveListenPort(listenPortInput, listenPort || 9090);
      if (!agentName.trim()) throw new Error("AI agent name is required");
      if (nextLogMode !== "ghost" && passphrase.trim().length < 4) {
        throw new Error("Passphrase is required for safe AI mode (min 4 characters)");
      }
      await ensureAiProfile();
      const req = {
        config_path: null,
        agent_name: agentName.trim(),
        listen_port: nextListenPort,
        transport,
        log_mode: nextLogMode,
        passphrase: nextLogMode === "ghost" ? "" : passphrase
      };
      const next = await invokeOrThrow<AppSnapshot>("runtime_start", { req });
      await applySnapshot(next, true);
      setListenPort(nextListenPort);
      if (nextLogMode !== "ghost") {
        setPassphrase("");
      }
      setUiFeedback(
        `AI agent '${req.agent_name}' started (${providerLabel(aiProvider)}${aiModel.trim() ? ` • ${aiModel.trim()}` : ""} • ${transportLabel(transport)} • ${nextLogMode} • :${nextListenPort}).`,
        false
      );
      return;
    }
    const nextLogMode = logModeForTransport(transport, logMode);
    const nextListenPort = resolveListenPort(listenPortInput, listenPort || 9090);
    if (!agentName.trim()) throw new Error("Agent name is required");
    if (nextLogMode !== "ghost" && passphrase.trim().length < 4) {
      throw new Error("Passphrase is required (min 4 characters)");
    }
    await ensureHumanProfile();
    const req = {
      config_path: nextLogMode === "ghost" ? null : (configPath.trim() || null),
      agent_name: agentName.trim(),
      listen_port: nextListenPort,
      transport,
      log_mode: nextLogMode,
      passphrase: nextLogMode === "ghost" ? "" : passphrase
    };
    const next = await invokeOrThrow<AppSnapshot>("runtime_start", { req });
    await applySnapshot(next, true);
    setListenPort(nextListenPort);
    if (nextLogMode !== "ghost") {
      setPassphrase("");
    }
    setUiFeedback(`Agent '${req.agent_name}' started. Wait a few seconds before generating an invite.`, false);
    try {
      const receiveDir = await invokeOrThrow<string>("get_receive_dir");
      if (receiveDir.trim()) {
        setReceiveDirInput(receiveDir.trim());
      }
    } catch {}
  }

  async function stopRuntime(): Promise<void> {
    const wasGhost = (snapshotRef.current?.runtime?.mode || "") === "ghost";
    const next = await invokeOrThrow<AppSnapshot>("runtime_stop", { agent: activeAgentName });
    await applySnapshot(next, true);
    if (wasGhost) {
      await clearClipboardBestEffort();
      clearSensitiveUiMemory();
      await scrubBrowserResidue();
    }
    setUiFeedback(`Agent '${activeAgentName || "-"}' stopped`, false);
  }

  async function destroyAgent(agentNameToDestroy: string): Promise<void> {
    const trimmed = agentNameToDestroy.trim();
    if (!trimmed) throw new Error("Agent name is required");
    await invokeOrThrow<AppSnapshot>("runtime_destroy_agent", { agent: trimmed });
    clearAgentUiState(trimmed);
    setPendingAgentDestroy(null);
    setUiFeedback(`Agent '${trimmed}' permanently deleted`, false);
  }

  async function destroyAllAgents(): Promise<void> {
    await invokeOrThrow<AppSnapshot>("runtime_destroy_all_agents");
    clearAllAgentUiState();
    setPendingAgentDestroy(null);
    setUiFeedback("All agents permanently deleted", false);
  }

  async function selectAgent(name: string): Promise<void> {
    const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: name });
    await applySnapshot(next, true);
    setOpenConversationMenuKey(null);
  }

  async function sendMessage(): Promise<void> {
    const message = messageInput.trim();
    const transferPath = pendingFilePath.trim();
    if (!message && !transferPath) return;
    if (transferPath && transferSubmitLock) return;
    forceScrollToBottomRef.current = true;
    await ensureBackendActiveAgent(activeAgentName);

    const conv = getActiveConversation(activeAgentName);
    if (!conv) return;
    const targetAiAgent = aiAgentNameFromDid(conv.did);

    if (message) {
      if (targetAiAgent) {
        if (activeAgentName && targetAiAgent === activeAgentName) {
          const previousCount = conv.messages.length;
          await invokeOrThrow<void>("runtime_send_console_input", { message });
          appendConversationMessage(activeAgentName, conversationMapForAgent(activeAgentName), conv.key, {
            direction: "out",
            sender: "you",
            text: message,
            tsMs: Date.now()
          });
          setMessageInput("");
          forceRender();
          void waitForAiConversationUpdate(activeAgentName, targetAiAgent, previousCount).catch((err) =>
            setUiFeedback(String(err), true)
          );
        } else {
          const requester =
            activeAgentName && activeAgentName.trim() && activeAgentName.trim() !== targetAiAgent
              ? activeAgentName.trim()
              : null;
          const thread = await invokeOrThrow<AiAgentThreadState>("ai_agent_send_message", {
            req: {
              ai_agent: targetAiAgent,
              requester_agent: requester,
              message
            }
          });
          applyAiThreadToConversation(activeAgentName, targetAiAgent, thread);
          setMessageInput("");
          forceRender();
        }
      } else if (conv.type === "group") {
        const groupId = groupIdFromConversationKey(conv.key);
        const selectedGroup =
          (groupId && mailboxGroups(currentRuntime()).find((group) => group.group_id === groupId)) ||
          selectedMailboxGroup(currentRuntime(), activeAgentName);
        if (!groupId) throw new Error("Select a mailbox group first");
        if (!selectedGroup) {
          setSelectedGroupForAgent(activeAgentName, groupId);
        }
        rememberLocalGroupOutgoing(activeAgentName, groupId, message);
        appendConversationMessage(activeAgentName, conversationMapForAgent(activeAgentName), conv.key, {
          direction: "out",
          sender: "you",
          text: message
        });
        forceRender();
        await invokeOrThrow<void>("runtime_send_group_message", { groupId, message });
        setMessageInput("");
      } else {
        if (!conv.did) throw new Error("Select a DM conversation");
        appendConversationMessage(activeAgentName, conversationMapForAgent(activeAgentName), conv.key, {
          direction: "out",
          sender: "you",
          text: message,
          localPending: true
        });
        forceRender();
        await invokeOrThrow<void>("runtime_set_selected_peer", { peer: conv.did });
        setSelectedPeerForAgent(activeAgentName, conv.did);
        await invokeOrThrow<void>("runtime_send_message", { message });
        setMessageInput("");
      }
    }

    if (transferPath) {
      if (targetAiAgent) {
        throw new Error("AI agent chats do not support file/folder transfer yet");
      }
      if (conv.type === "group") {
        const groupId = groupIdFromConversationKey(conv.key);
        if (!groupId) {
          throw new Error("Select a mailbox group first");
        }
        setTransferSubmitLock(true);
        try {
          await invokeOrThrow<void>("runtime_transfer_group", { groupId, path: transferPath });
        } finally {
          setTransferSubmitLock(false);
        }
        rememberLocalGroupOutgoing(
          activeAgentName,
          groupId,
          pendingTransferLabel(pendingTransferKind, transferPath),
          true
        );
        appendConversationMessage(activeAgentName, conversationMapForAgent(activeAgentName), conv.key, {
          direction: "out",
          sender: "you",
          text: pendingTransferLabel(pendingTransferKind, transferPath),
          isTransfer: true
        });
      } else {
        if (!conv.did) {
          throw new Error("File transfer requires an active DM conversation");
        }
        await sendTransfer(transferPath);
        appendConversationMessage(activeAgentName, conversationMapForAgent(activeAgentName), conv.key, {
          direction: "out",
          sender: "you",
          text: pendingTransferLabel(pendingTransferKind, transferPath),
          isTransfer: true
        });
      }
      setPendingFilePath("");
      setPendingTransferKind("file");
    }
    forceRender();
  }

  async function sendTransfer(path: string): Promise<void> {
    if (transferSubmitLock) return;
    const normalizedPath = path.trim();
    if (!normalizedPath) return;
    await ensureBackendActiveAgent(activeAgentName);

    const conv = getActiveConversation(activeAgentName);
    if (!conv || conv.type !== "dm" || !conv.did) throw new Error("Transfer requires an active DM conversation");

    const runtime = currentRuntime();
    if (hasOutgoingTransferForUi(runtime, activeAgentName)) {
      throw new Error("Another outgoing transfer is already in progress");
    }

    const txCtx = transferContextForAgent(activeAgentName);
    txCtx.outgoingDid = conv.did;
    txCtx.outgoingSession = null;
    txCtx.lastPackedDid = conv.did;
    txCtx.sessionDid = Object.create(null);
    txCtx.localStage = "packing";

    setTransferSubmitLock(true);
    forceRender();
    try {
      await invokeOrThrow<void>("runtime_transfer", {
        req: { peer: conv.did, path: normalizedPath }
      });
    } catch (error) {
      if (txCtx.outgoingDid === conv.did && txCtx.localStage === "packing") {
        resetTransferContextState(txCtx);
        forceRender();
      }
      throw error;
    } finally {
      setTransferSubmitLock(false);
    }
  }

  async function openTransferPicker(): Promise<void> {
    setComposerMenuOpen(false);
    const selected = await invokeOrThrow<TransferPickerSelection | null>("pick_transfer_path");
    if (!selected?.path?.trim()) return;
    setPendingFilePath(selected.path.trim());
    setPendingTransferKind(selected.is_dir ? "folder" : "file");
  }

  async function openTransferFilePicker(): Promise<void> {
    setComposerMenuOpen(false);
    const selected = await invokeOrThrow<string | null>("pick_transfer_file");
    if (!selected?.trim()) return;
    setPendingFilePath(selected.trim());
    setPendingTransferKind("file");
  }

  async function openTransferFolderPicker(): Promise<void> {
    setComposerMenuOpen(false);
    const selected = await invokeOrThrow<string | null>("pick_transfer_folder");
    if (!selected?.trim()) return;
    setPendingFilePath(selected.trim());
    setPendingTransferKind("folder");
  }

  async function connectByInvite(): Promise<void> {
    const code = normalizeInviteCode(inviteCodeInput);
    if (!code) return;
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_connect_invite", { code });
    setInviteCodeInput("");
    setComposerMenuOpen(false);
  }

  async function connectByDid(): Promise<void> {
    const did = didConnectInput.trim();
    if (!did) return;
    if (!did.startsWith("did:qypha:")) {
      throw new Error("Enter a shareable Qypha DID");
    }
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_connect_did", { did });
    setDidConnectInput("");
    setComposerMenuOpen(false);
  }

  async function regenerateMailboxGroupInvite(groupId: string): Promise<void> {
    const trimmed = groupId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    const group = mailboxGroupList.find((entry) => entry.group_id === trimmed) || null;
    if (group && !isLocallyOwnedMailboxGroup(group)) {
      throw new Error("Only the group owner can generate a fresh invite");
    }
    const runtimeValue = currentRuntime();
    const previousRevision = Number(runtimeValue?.latest_group_invite_revision || 0);
    const previousCode = runtimeValue?.latest_group_invite_code?.trim() || "";
    const previousEpoch = group?.mailbox_epoch ?? null;
    if (group?.anonymous_group && !group.owner_special_id) {
      throw new Error("Anonymous group owner handle is missing");
    }
    const code = await requestInviteCode(
      "group",
      "runtime_regenerate_group_invite",
      { groupId: trimmed },
      previousRevision,
      previousCode
    );
    setLatestGroupInviteCode(code);
    setLatestGroupInviteContext({
      groupId: trimmed,
      groupName: group ? mailboxGroupLabel(group) : null
    });
    setSelectedInviteGroupId(trimmed);
    setInviteHubSection("group");
    const nextSnapshot = await refreshSnapshot(true);
    const nextGroup =
      nextSnapshot.runtime?.mailbox_groups?.find((entry) => entry.group_id === trimmed) || null;
    if (group?.anonymous_group) {
      const nextEpoch = typeof nextGroup?.mailbox_epoch === "number" ? nextGroup.mailbox_epoch : previousEpoch;
      setLatestGroupInviteContext({
        groupId: trimmed,
        groupName: nextGroup ? mailboxGroupLabel(nextGroup) : group ? mailboxGroupLabel(group) : null,
        invalidatesPrevious: true,
        previousEpoch,
        currentEpoch: nextEpoch
      });
      if (
        typeof previousEpoch === "number" &&
        typeof nextEpoch === "number" &&
        nextEpoch > previousEpoch
      ) {
        setUiFeedback(
          `Ghost invite rotated to epoch ${nextEpoch}. Older invites are now invalid.`,
          false
        );
      } else {
        setUiFeedback("Ghost invite refreshed. Treat older invites as invalid.", false);
      }
      return;
    }
    setUiFeedback("Mailbox group invite refreshed", false);
  }

  async function acceptGroupHandshakeOffer(senderMemberId: string): Promise<void> {
    const trimmed = senderMemberId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    clearConversationDeleted(activeAgentName, trimmed);
    const map = conversationMapForAgent(activeAgentName);
    const dmKey = `dm:${trimmed}`;
    ensureConversation(map, dmKey, "dm", displayNameForDid(currentRuntime(), trimmed, trimmed), trimmed, true);
    const acceptedConversation = map.get(dmKey) || null;
    if (acceptedConversation && acceptedConversation.messages.length === 0) {
      appendConversationMessage(activeAgentName, map, dmKey, {
        direction: "in",
        sender: "system",
        text: "Direct trust accepted • ready to chat"
      });
    }
    await invokeOrThrow<void>("runtime_accept_group_handshake_offer", { senderMemberId: trimmed });
    forceRender();
    setUiFeedback("Direct trust offer accepted via secure direct-connect flow", false);
  }

  async function rejectGroupHandshakeOffer(senderMemberId: string): Promise<void> {
    const trimmed = senderMemberId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_reject_group_handshake_offer", { senderMemberId: trimmed });
    setUiFeedback(`Direct trust request rejected for ${trimmed}`, false);
  }

  async function blockGroupHandshakeOffer(senderMemberId: string): Promise<void> {
    const trimmed = senderMemberId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_block_group_handshake_offer", { senderMemberId: trimmed });
    setUiFeedback(`${trimmed} can no longer send direct trust requests`, false);
  }

  async function sendGroupHandshakeInvite(groupId: string, memberId: string): Promise<void> {
    const trimmedGroupId = groupId.trim();
    const trimmedMemberId = memberId.trim();
    if (!trimmedGroupId || !trimmedMemberId) return;
    const remaining = remainingGroupHandshakeInviteCooldownMs(activeAgentName, trimmedMemberId);
    if (remaining > 0) {
      setUiFeedback(
        `Direct trust cooldown active for ${trimmedMemberId} • retry in ${Math.ceil(remaining / 1000)}s`,
        true
      );
      return;
    }
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_send_group_handshake_invite", {
      groupId: trimmedGroupId,
      memberId: trimmedMemberId
    });
    rememberGroupHandshakeInviteCooldown(activeAgentName, trimmedMemberId);
    setUiFeedback(`Direct trust request sent to ${trimmedMemberId}`, false);
  }

  async function setHandshakeRequestBlock(memberId: string, blocked: boolean): Promise<void> {
    const trimmed = memberId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_set_handshake_request_block", {
      memberId: trimmed,
      blocked
    });
    setUiFeedback(
      blocked
        ? `${trimmed} can no longer send handshake requests`
        : `${trimmed} can send handshake requests again`,
      false
    );
  }

  async function setHandshakeRequestBlockAll(blocked: boolean): Promise<void> {
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_set_handshake_request_block_all", { blocked });
    setUiFeedback(
      blocked ? "All incoming handshake requests are blocked" : "Incoming handshake requests are allowed",
      false
    );
  }

  async function setAgentIncomingConnectBlockAll(agentName: string, blocked: boolean): Promise<void> {
    const targetName = agentName.trim();
    if (!targetName) return;
    const next = await invokeOrThrow<AppSnapshot>("runtime_select_agent", { agentName: targetName });
    await applySnapshot(next, true);
    if (!next.runtime?.running) {
      throw new Error("Start this agent before changing invite lock state");
    }
    await invokeOrThrow<void>("runtime_set_incoming_connect_block_all", { blocked });
    setUiFeedback(
      blocked
        ? `Incoming DID/invite first-contact requests locked for '${targetName}'`
        : `Incoming DID/invite first-contact requests unlocked for '${targetName}'`,
      false
    );
  }

  async function kickMailboxGroupMember(memberId: string): Promise<void> {
    const trimmed = memberId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_kick_group_member", { memberId: trimmed });
    setUiFeedback(`Mailbox rotation requested for ${trimmed}`, false);
  }

  async function setMailboxGroupJoinLock(group: MailboxGroupSnapshot, locked: boolean): Promise<void> {
    const groupId = group.group_id.trim();
    if (!groupId) return;
    await ensureBackendActiveAgent(activeAgentName);
    await invokeOrThrow<void>("runtime_set_group_join_lock", { groupId, locked });
    setUiFeedback(
      locked
        ? `Mailbox group '${mailboxGroupLabel(group)}' locked`
        : `Mailbox group '${mailboxGroupLabel(group)}' unlocked`,
      false
    );
  }

  function canKickMailboxGroupMember(group: MailboxGroupSnapshot, memberId: string): boolean {
    if (!group || group.anonymous_group) return false;
    if (!isLocallyOwnedMailboxGroup(group)) return false;
    if (!memberId || memberId === group.local_member_id) return false;
    const ownerControlledMatches = mailboxGroupList.filter(
      (candidate) =>
        !candidate.anonymous_group &&
        isLocallyOwnedMailboxGroup(candidate) &&
        (candidate.known_member_ids || []).includes(memberId)
    );
    return ownerControlledMatches.length === 1;
  }

  async function applyIncomingContactDecision(action: "accept" | "reject", did: string): Promise<void> {
    const trimmed = String(did || "").trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    setContactRequestActionDid(trimmed);
    try {
      if (action === "accept") {
        await invokeOrThrow<void>("runtime_accept", { peer: trimmed });
      } else {
        await invokeOrThrow<void>("runtime_reject", { peer: trimmed });
      }
    } finally {
      setContactRequestActionDid((current) => (current === trimmed ? null : current));
    }
  }

  async function applyTransferDecision(
    action: "accept" | "reject" | "always" | "ask",
    did: string,
    approvalKey?: string | null
  ): Promise<void> {
    await ensureBackendActiveAgent(activeAgentName);
    const actionKey = (approvalKey || did || "").trim();
    if (actionKey) {
      setTransferApprovalActionKey(actionKey);
    }
    try {
      if (action === "accept") {
        await invokeOrThrow<void>("runtime_accept", { peer: did });
      } else if (action === "reject") {
        await invokeOrThrow<void>("runtime_reject", { peer: did });
      } else if (action === "always") {
        await invokeOrThrow<void>("runtime_accept_always", { peer: did });
        transferPolicyMapForAgent(activeAgentName).set(did, "always");
      } else {
        await invokeOrThrow<void>("runtime_accept_ask", { peer: did });
        transferPolicyMapForAgent(activeAgentName).set(did, "ask");
      }
    } finally {
      setTransferApprovalActionKey((current) => (current === actionKey ? null : current));
    }
  }

  async function exportGhostHandoff(handoffId: string): Promise<void> {
    const trimmed = handoffId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    setHandoffActionId(trimmed);
    try {
      await invokeOrThrow<void>("runtime_export_handoff", { handoffId: trimmed });
    } finally {
      setHandoffActionId((current) => (current === trimmed ? null : current));
    }
  }

  async function discardGhostHandoff(handoffId: string): Promise<void> {
    const trimmed = handoffId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    setHandoffActionId(trimmed);
    try {
      await invokeOrThrow<void>("runtime_discard_handoff", { handoffId: trimmed });
    } finally {
      setHandoffActionId((current) => (current === trimmed ? null : current));
    }
  }

  async function applyGroupFileOfferDecision(action: "accept" | "reject", manifestId: string): Promise<void> {
    const trimmed = manifestId.trim();
    if (!trimmed) return;
    await ensureBackendActiveAgent(activeAgentName);
    setGroupOfferActionId(trimmed);
    try {
      if (action === "accept") {
        await invokeOrThrow<void>("runtime_accept_group_file_offer", { manifestId: trimmed });
      } else {
        await invokeOrThrow<void>("runtime_reject_group_file_offer", { manifestId: trimmed });
      }
    } catch (error) {
      setGroupOfferActionId((current) => (current === trimmed ? null : current));
      throw error;
    }
  }

  function inferTransferPolicy(runtime: RuntimeSnapshot | null, did: string | null): "ask" | "always" {
    if (runtime?.mode === "ghost") return "ask";
    if (!did) return "ask";
    return transferPolicyMapForAgent(activeAgentName).get(did) || "ask";
  }

  const runtime =
    snapshot?.active_agent && snapshot.active_agent === activeAgentName ? snapshot.runtime || null : null;
  const isRuntimeGhost = !!runtime?.running && runtime.mode === "ghost";
  const selectedLogMode = logModeForTransport(transport, logMode);
  const isGhost = isRuntimeGhost || (!runtime?.running && selectedLogMode === "ghost");
  const showLogModePicker = transport === "tor";
  const showConfigPanel = !isGhost;
  const activeAgentCard = snapshot?.agents.find((agent) => agent.name === activeAgentName) || null;
  const sortedAgentCards = useMemo(
    () => [...(snapshot?.agents || [])].sort((a, b) => a.name.localeCompare(b.name)),
    [snapshot?.agents]
  );
  const humanAgentCards = useMemo(
    () => sortedAgentCards.filter((agent) => normalizeAgentType(agent.agent_type) === "human"),
    [sortedAgentCards]
  );
  const aiAgentCards = useMemo(
    () => sortedAgentCards.filter((agent) => normalizeAgentType(agent.agent_type) === "ai"),
    [sortedAgentCards]
  );
  const activeConversation = getActiveConversation(activeAgentName);
  const activeConversationKey = activeConversationKeyForAgent(activeAgentName);
  const activeConversationGroupId =
    activeConversation?.type === "group" ? groupIdFromConversationKey(activeConversation.key) : null;
  const activeAiConversationAgent =
    activeConversation?.type === "dm" ? aiAgentNameFromDid(activeConversation.did) : null;
  const activeAgentIsAi = normalizeAgentType(activeAgentCard?.agent_type) === "ai";
  const activeAiConversationCard =
    (activeAiConversationAgent &&
      (snapshot?.agents.find((agent) => agent.name === activeAiConversationAgent) || null)) ||
    null;
  const conversationMap = conversationMapForAgent(activeAgentName);
  const mailboxGroupList = runtime?.mailbox_groups || [];
  const displayedRuntimeLogs = useMemo(
    () => collapseRuntimeLogLines((runtime?.recent_logs || []).filter((line) => !isStructuredTransferLogLine(line))),
    [runtime?.recent_logs]
  );
  const handshakeRequestPolicy = runtime?.handshake_request_policy || {
    block_all: false,
    blocked_member_ids: []
  };
  const blockedHandshakeMemberIds = useMemo(
    () => new Set((handshakeRequestPolicy.blocked_member_ids || []).map((memberId) => memberId.trim())),
    [handshakeRequestPolicy.blocked_member_ids]
  );
  const currentMailboxGroup = selectedMailboxGroup(runtime, activeAgentName);
  const orderedMailboxGroups = useMemo(() => {
    return [...mailboxGroupList].sort((a, b) => {
      const aOwned = isLocallyOwnedMailboxGroup(a);
      const bOwned = isLocallyOwnedMailboxGroup(b);
      if (aOwned !== bOwned) return aOwned ? -1 : 1;
      return mailboxGroupLabel(a).localeCompare(mailboxGroupLabel(b));
    });
  }, [mailboxGroupList]);
  const selectedInviteGroup = useMemo(
    () => orderedMailboxGroups.find((group) => group.group_id === selectedInviteGroupId) || null,
    [orderedMailboxGroups, selectedInviteGroupId]
  );
  const selectedInviteGroupIsOwner = isLocallyOwnedMailboxGroup(selectedInviteGroup);
  const selectedInviteGroupInviteCode = useMemo(() => {
    if (!latestGroupInviteCode) return "";
    if (!selectedInviteGroup) return latestGroupInviteCode;
    if (!isLocallyOwnedMailboxGroup(selectedInviteGroup)) return "";
    if (latestGroupInviteContext?.groupId && latestGroupInviteContext.groupId === selectedInviteGroup.group_id) {
      return latestGroupInviteCode;
    }
    const selectedLabel = mailboxGroupLabel(selectedInviteGroup).trim().toLowerCase();
    const contextLabel = latestGroupInviteContext?.groupName?.trim().toLowerCase() || "";
    if (!latestGroupInviteContext?.groupId && contextLabel && contextLabel === selectedLabel) {
      return latestGroupInviteCode;
    }
    return "";
  }, [latestGroupInviteCode, latestGroupInviteContext, selectedInviteGroup]);
  const selectedInviteGroupRotationNotice = useMemo(() => {
    if (!selectedInviteGroup?.anonymous_group) return null;
    if (!latestGroupInviteContext?.groupId || latestGroupInviteContext.groupId !== selectedInviteGroup.group_id) {
      return null;
    }
    if (!latestGroupInviteContext.invalidatesPrevious) return null;
    return {
      previousEpoch:
        typeof latestGroupInviteContext.previousEpoch === "number"
          ? latestGroupInviteContext.previousEpoch
          : null,
      currentEpoch:
        typeof latestGroupInviteContext.currentEpoch === "number"
          ? latestGroupInviteContext.currentEpoch
          : selectedInviteGroup.mailbox_epoch
    };
  }, [latestGroupInviteContext, selectedInviteGroup]);
  const pendingCreatedGroupInvite = useMemo(() => {
    if (!latestGroupInviteCode) return null;
    if (!latestGroupInviteContext?.groupName || latestGroupInviteContext.groupId) return null;
    return {
      groupName: latestGroupInviteContext.groupName.trim() || "New group"
    };
  }, [latestGroupInviteCode, latestGroupInviteContext]);
  const pendingHandshakeOffers = useMemo(
    () =>
      (runtime?.group_events || []).filter(
        (event) =>
          event.kind === "direct_handshake_offer" &&
          !!event.invite_code &&
          !handshakeRequestPolicy.block_all &&
          !blockedHandshakeMemberIds.has((event.sender_member_id || "").trim())
      ),
    [blockedHandshakeMemberIds, handshakeRequestPolicy.block_all, runtime?.group_events]
  );
  const pendingGroupOffersForActiveGroup = useMemo(() => {
    if (!activeConversation || activeConversation.type !== "group") return [] as PendingGroupFileOffer[];
    const activeGroupId = currentMailboxGroup?.group_id || groupIdFromConversationKey(activeConversationKey);
    if (!activeGroupId) return [] as PendingGroupFileOffer[];
    const events = (runtime?.group_events || []).filter((event) => event.group_id === activeGroupId);
    const resolved = new Set<string>();
    for (const event of events) {
      if (
        (event.kind === "file_offer_accepted" || event.kind === "file_offer_rejected") &&
        event.manifest_id
      ) {
        resolved.add(event.manifest_id);
      }
    }
    const offers = new Map<string, PendingGroupFileOffer>();
    for (const event of events) {
      if (event.kind !== "file_offer_pending" || !event.manifest_id || resolved.has(event.manifest_id)) {
        continue;
      }
      offers.set(event.manifest_id, {
        manifest_id: event.manifest_id,
        group_id: event.group_id,
        group_name: event.group_name,
        anonymous_group: event.anonymous_group,
        sender_member_id: event.sender_member_id,
        member_display_name: event.member_display_name,
        filename: event.filename,
        size_bytes: event.size_bytes,
        message: event.message,
        ts_ms: event.ts_ms
      });
    }
    return [...offers.values()].sort((a, b) => (a.ts_ms || 0) - (b.ts_ms || 0));
  }, [runtime?.group_events, activeConversation, activeConversationKey, currentMailboxGroup]);
  const pendingGroupOfferByManifestId = useMemo(() => {
    return new Map(
      pendingGroupOffersForActiveGroup.map((offer) => [offer.manifest_id, offer] as const)
    );
  }, [pendingGroupOffersForActiveGroup]);
  const activeGroupMemberIds = useMemo(() => {
    if (!currentMailboxGroup || currentMailboxGroup.anonymous_group) return [] as string[];
    const seen = new Set<string>();
    const ordered: string[] = [];
    for (const memberId of [
      currentMailboxGroup.local_member_id,
      currentMailboxGroup.owner_member_id,
      ...(currentMailboxGroup.known_member_ids || [])
    ]) {
      const normalized = memberId?.trim();
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      ordered.push(normalized);
    }
    return ordered;
  }, [currentMailboxGroup]);
  const mailboxSecurityNotes = useMemo(() => {
    const notes: string[] = [];
    if (!runtime) return notes;
    notes.push("Mailbox groups always use Tor outbound polling and never open peer routes during join.");
    if (runtime.transport === "internet") {
      notes.push("Internet transport only affects direct peers. Group plane still stays on Tor mailbox.");
    }
    if (runtime.mode === "ghost") {
      notes.push("Ghost groups are anonymous, RAM-only, and block /invite_h direct trust promotion.");
    } else {
      notes.push("Safe identified groups expose member IDs, but direct trust still requires explicit /invite_h.");
    }
    if (mailboxGroupList.some((group) => group.anonymous_group)) {
      notes.push("Anonymous groups never show member DID and can never bridge into a direct peer route.");
    }
    return notes;
  }, [mailboxGroupList, runtime]);
  const inviteSecuritySummary = useMemo(() => {
    if (selectedInviteGroup?.anonymous_group) {
      const security = mailboxGroupAnonymousSecurityLabel(selectedInviteGroup) || "legacy";
      if (security === "v2 secure") {
        return "Ghost anonymous v2 groups use separate content and writer epochs. Fresh invite rotation invalidates older invites and writer credentials.";
      }
      return "Legacy anonymous groups keep anonymity, but do not expose the newer v2 writer-credential posture in the UI yet.";
    }
    if (runtime?.mode === "ghost") {
      return "Ghost group invites stay anonymous, memory-only, and never bridge into direct peer routes.";
    }
    if (runtime?.transport === "internet") {
      return "Direct peers may use internet transport, but mailbox group invites stay on the Tor-backed group plane.";
    }
    return mailboxSecurityNotes[0] || "Mailbox group joins stay on Tor-backed transport and do not open peer routes during join.";
  }, [mailboxSecurityNotes, runtime, selectedInviteGroup]);
  const onlineDidSet = useMemo(() => {
    return new Set(
      (runtime?.peers || [])
        .filter((peer) => isPeerOnlineStatus(peer.status))
        .map((peer) => peer.did)
    );
  }, [runtime?.peers]);
  const visiblePeers = useMemo(() => {
    const deduped = new Map<string, PeerSnapshot>();
    for (const peer of runtime?.peers || []) {
      const did = peer.did?.trim();
      if (!did || !onlineDidSet.has(did)) continue;
      const nextPeer: PeerSnapshot = {
        ...peer,
        did,
        name: cleanPeerName(peer.name, did)
      };
      const existing = deduped.get(did);
      if (!existing || (!isPeerOnlineStatus(existing.status) && isPeerOnlineStatus(nextPeer.status))) {
        deduped.set(did, nextPeer);
      }
    }
    return [...deduped.values()].sort((a, b) => {
      const aOnline = isPeerOnlineStatus(a.status);
      const bOnline = isPeerOnlineStatus(b.status);
      if (aOnline !== bOnline) return aOnline ? -1 : 1;
      return cleanPeerName(a.name, a.did).localeCompare(cleanPeerName(b.name, b.did));
    });
  }, [runtime?.peers, onlineDidSet]);
  const panelPeers = useMemo(() => {
    return [...(runtime?.peers || [])]
      .map((peer) => ({
        ...peer,
        did: String(peer.did || "").trim(),
        name: cleanPeerName(peer.name, peer.did)
      }))
      .filter((peer) => peer.did)
      .sort((a, b) => {
        const rankDiff = peerPanelStatusRank(a.status) - peerPanelStatusRank(b.status);
        if (rankDiff !== 0) return rankDiff;
        return cleanPeerName(a.name, a.did).localeCompare(cleanPeerName(b.name, b.did));
      });
  }, [runtime?.peers]);
  const pendingContactRequests = useMemo(() => {
    return [...(runtime?.pending_contact_requests || [])].sort((a, b) => b.ts_ms - a.ts_ms);
  }, [runtime?.pending_contact_requests]);
  const activeGroupMemberDisplayNames = useMemo(() => {
    const names = new Map<string, string>();
    if (!activeConversationGroupId || currentMailboxGroup?.anonymous_group) return names;
    for (const peer of visiblePeers) {
      if (peer.name?.trim()) {
        names.set(peer.did, cleanPeerName(peer.name.trim(), peer.did));
      }
    }
    for (const event of runtime?.group_events || []) {
      if (event.group_id !== activeConversationGroupId) continue;
      const displayName = event.member_display_name?.trim();
      if (!displayName || isDid(displayName)) continue;
      const senderMemberId = event.sender_member_id?.trim();
      if (senderMemberId) {
        names.set(senderMemberId, cleanPeerName(displayName, senderMemberId));
      }
      const memberId = event.member_id?.trim();
      if (memberId) {
        names.set(memberId, cleanPeerName(displayName, memberId));
      }
      const kickedMemberId = event.kicked_member_id?.trim();
      if (kickedMemberId) {
        names.delete(kickedMemberId);
      }
    }
    return names;
  }, [activeConversationGroupId, currentMailboxGroup?.anonymous_group, runtime?.group_events, visiblePeers]);
  const activeConversationGroupLabel = useMemo(() => {
    if (currentMailboxGroup) return mailboxGroupLabel(currentMailboxGroup);
    if (activeConversation?.type === "group" && activeConversation.title?.trim()) {
      return activeConversation.title.trim();
    }
    return activeConversationGroupId || "Group Chat";
  }, [currentMailboxGroup, activeConversation, activeConversationGroupId]);
  const observedActiveGroupMembers = useMemo(() => {
    if (!activeConversationGroupId || currentMailboxGroup?.anonymous_group) return [] as Array<{ memberId: string; label: string }>;
    return [...activeGroupMemberDisplayNames.entries()]
      .map(([memberId, label]) => ({ memberId, label }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [activeConversationGroupId, currentMailboxGroup?.anonymous_group, activeGroupMemberDisplayNames]);

  const orderedConversations = useMemo(() => {
    const needle = conversationFilter.trim().toLowerCase();
    const controlDid =
      activeAgentIsAi && activeAgentName ? localAiDid(activeAgentName) : null;
    const entries = [...conversationMap.values()]
      .filter((c) => shouldRenderConversationInList(c))
      .filter((c) => (controlDid ? c.did === controlDid : !isLocalAiDid(c.did)))
      .filter((c) => {
        if (!needle) return true;
        const inTitle = c.title.toLowerCase().includes(needle);
        const inDid = (c.did || "").toLowerCase().includes(needle);
        const inLast = (c.messages[c.messages.length - 1]?.text || "").toLowerCase().includes(needle);
        return inTitle || inDid || inLast;
      });
    return sortConversationsByActivity(entries);
  }, [activeAgentIsAi, activeAgentName, conversationMap, renderEpoch, conversationFilter, onlineDidSet]);

  const pendingIncomingTransferOffersForActiveDid = useMemo(() => {
    if (!activeConversation || activeConversation.type !== "dm" || !activeConversation.did) {
      return [] as PendingIncomingTransferOffer[];
    }
    const activeDid = activeConversation.did;
    const latestByKey = new Map<string, TransferRuntimeEvent>();
    for (const event of runtime?.transfer_events || []) {
      const did = canonicalDidForTransferEvent(event);
      if (!did || did !== activeDid) continue;
      if (!matchesIncomingTransferDirection(event.direction)) continue;
      latestByKey.set(transferEventKey(event, did), event);
    }
    return [...latestByKey.entries()]
      .filter(([, event]) => event.event === "incoming_pending")
      .map(([transferKey, event]) => ({
        transfer_key: transferKey,
        did: activeDid,
        peer_label: displayNameForDid(runtime, activeDid, event.peer_name || activeDid),
        filename: event.filename,
        session_id: event.session_id,
        ts_ms: event.ts_ms
      }))
      .sort((a, b) => (a.ts_ms || 0) - (b.ts_ms || 0));
  }, [runtime, activeConversation]);
  const pendingIncomingTransferOfferByKey = useMemo(() => {
    return new Map(
      pendingIncomingTransferOffersForActiveDid.map((offer) => [offer.transfer_key, offer] as const)
    );
  }, [pendingIncomingTransferOffersForActiveDid]);

  useEffect(() => {
    if (!transferApprovalActionKey) return;
    if (pendingIncomingTransferOfferByKey.has(transferApprovalActionKey)) return;
    setTransferApprovalActionKey(null);
  }, [transferApprovalActionKey, pendingIncomingTransferOfferByKey]);

  useEffect(() => {
    if (!groupOfferActionId) return;
    if (pendingGroupOffersForActiveGroup.some((offer) => offer.manifest_id === groupOfferActionId)) return;
    setGroupOfferActionId(null);
  }, [groupOfferActionId, pendingGroupOffersForActiveGroup]);

  useEffect(() => {
    setGroupMembersPanelOpen(false);
  }, [activeConversationKey]);

  useEffect(() => {
    setInviteHubSection("direct");
    setSelectedInviteGroupId(null);
    setLatestGroupInviteContext(null);
  }, [activeAgentName]);

  useEffect(() => {
    if (!mailboxGroupList.length) {
      if (selectedInviteGroupId) {
        setSelectedInviteGroupId(null);
      }
      return;
    }
    if (selectedInviteGroupId && mailboxGroupList.some((group) => group.group_id === selectedInviteGroupId)) {
      return;
    }
    const hasPendingCreatedGroup =
      !!latestGroupInviteContext?.groupName && !latestGroupInviteContext.groupId;
    const matchedPendingGroup =
      hasPendingCreatedGroup
        ? mailboxGroupList.find(
            (group) =>
              mailboxGroupLabel(group).trim().toLowerCase() ===
              latestGroupInviteContext.groupName?.trim().toLowerCase()
          ) || null
        : null;
    if (hasPendingCreatedGroup && !matchedPendingGroup) {
      if (selectedInviteGroupId) {
        setSelectedInviteGroupId(null);
      }
      return;
    }
    const preferredByContext =
      (latestGroupInviteContext?.groupId &&
        mailboxGroupList.find((group) => group.group_id === latestGroupInviteContext.groupId)) ||
      (latestGroupInviteContext?.groupName &&
        mailboxGroupList.find(
          (group) =>
            mailboxGroupLabel(group).trim().toLowerCase() ===
            latestGroupInviteContext.groupName?.trim().toLowerCase()
        )) ||
      null;
    const fallback = orderedMailboxGroups.find((group) => isLocallyOwnedMailboxGroup(group)) || orderedMailboxGroups[0];
    const nextGroup = preferredByContext || fallback || null;
    if (nextGroup && nextGroup.group_id !== selectedInviteGroupId) {
      setSelectedInviteGroupId(nextGroup.group_id);
    }
  }, [latestGroupInviteContext, mailboxGroupList, orderedMailboxGroups, selectedInviteGroupId]);

  useEffect(() => {
    if (!latestGroupInviteContext?.groupName || latestGroupInviteContext.groupId) return;
    const matchedGroup = mailboxGroupList.find(
      (group) =>
        isLocallyOwnedMailboxGroup(group) &&
        mailboxGroupLabel(group).trim().toLowerCase() === latestGroupInviteContext.groupName?.trim().toLowerCase()
    );
    if (!matchedGroup) return;
    setLatestGroupInviteContext((current) => {
      if (!current || current.groupId || current.groupName !== latestGroupInviteContext.groupName) {
        return current;
      }
      return {
        ...current,
        groupId: matchedGroup.group_id
      };
    });
    setSelectedInviteGroupId((current) => current || matchedGroup.group_id);
  }, [latestGroupInviteContext, mailboxGroupList]);

  useEffect(() => {
    if (!runtime?.running || !activeConversationGroupId) {
      lastMissingGroupRefreshRef.current = "";
      return;
    }
    if (currentMailboxGroup) {
      lastMissingGroupRefreshRef.current = "";
      return;
    }
    const refreshKey = `${getAgentKey(activeAgentName)}:${activeConversationGroupId}`;
    if (lastMissingGroupRefreshRef.current === refreshKey) {
      return;
    }
    if (inviteActionInFlightRef.current) {
      return;
    }
    lastMissingGroupRefreshRef.current = refreshKey;
    let disposed = false;
    void hydrateMissingMailboxGroupSnapshot(
      activeConversationGroupId,
      () => invokeOrThrow<AppSnapshot>("runtime_try_list_groups"),
      () => invokeOrThrow<AppSnapshot>("runtime_list_groups")
    )
      .then((next) => {
        if (disposed) {
          return;
        }
        if (!snapshotContainsMailboxGroup(next, activeConversationGroupId)) {
          lastMissingGroupRefreshRef.current = "";
        }
        return applySnapshot(next, true);
      })
      .catch(() => {
        lastMissingGroupRefreshRef.current = "";
        // best-effort refresh when the active group conversation exists
        // but the matching mailbox group snapshot has not reached the UI yet.
      });
    return () => {
      disposed = true;
    };
  }, [runtime?.running, activeAgentName, activeConversationGroupId, currentMailboxGroup]);

  useEffect(() => {
    if (!runtime?.running || !activeAgentName) return;
    if (inviteActionInFlightRef.current) return;
    if (mailboxGroupList.length > 0) return;
    const key = getAgentKey(activeAgentName);
    const now = Date.now();
    const last = lastGroupBootstrapAtByAgentRef.current.get(key) || 0;
    if (now - last < 5000) return;
    lastGroupBootstrapAtByAgentRef.current.set(key, now);
    void invokeOrThrow<AppSnapshot>("runtime_try_list_groups")
      .then((next) => applySnapshot(next, true))
      .catch(() => {
        // best-effort bootstrap so group-driven UI sections can hydrate after startup
      });
  }, [runtime?.running, activeAgentName, mailboxGroupList.length]);

  useEffect(() => {
    if (!runtime?.running || !activeAgentName) return;
    if (inviteActionInFlightRef.current) return;
    if ((runtime.peers || []).length > 0) return;
    const key = getAgentKey(activeAgentName);
    const now = Date.now();
    const last = lastPeerRefreshAtByAgentRef.current.get(key) || 0;
    if (now - last < PEER_REFRESH_MS) return;
    lastPeerRefreshAtByAgentRef.current.set(key, now);
    void invokeOrThrow<AppSnapshot>("runtime_try_list_peers")
      .then((next) => applySnapshot(next, true))
      .catch(() => {
        // best-effort bootstrap so peer-driven UI can hydrate without blocking user commands
      });
  }, [runtime?.running, activeAgentName, runtime?.peers?.length]);

  useEffect(() => {
    if (!runtime?.running || !activeAgentName) return;
    const startedAt = String(runtime.started_at || "").trim();
    if (!startedAt) return;
    const key = getAgentKey(activeAgentName);
    const sessionKey = `${startedAt}:${runtime.mode || ""}`;
    if (lastPeerSessionSyncByAgentRef.current.get(key) === sessionKey) return;
    lastPeerSessionSyncByAgentRef.current.set(key, sessionKey);

    let disposed = false;
    const timer = window.setTimeout(() => {
      if (disposed || inviteActionInFlightRef.current) return;
      void invokeOrThrow<AppSnapshot>("runtime_list_peers")
        .then((next) => {
          if (!disposed) {
            void applySnapshot(next, true);
          }
        })
        .catch(() => {
          // best-effort startup reconcile so the peer panel reflects `/all`
          // roster state, including offline known peers.
        });
    }, 600);

    return () => {
      disposed = true;
      window.clearTimeout(timer);
    };
  }, [runtime?.running, runtime?.started_at, runtime?.mode, activeAgentName]);

  useEffect(() => {
    if (!runtime?.running || !activeAgentName) return;
    const startedAt = String(runtime.started_at || "").trim();
    if (!startedAt) return;
    const key = getAgentKey(activeAgentName);
    const sessionKey = `${startedAt}:${runtime.mode || ""}`;
    if (lastGroupSessionSyncByAgentRef.current.get(key) === sessionKey) return;
    lastGroupSessionSyncByAgentRef.current.set(key, sessionKey);

    let disposed = false;
    const timer = window.setTimeout(() => {
      if (disposed || inviteActionInFlightRef.current) return;
      void invokeOrThrow<AppSnapshot>("runtime_list_groups")
        .then((next) => {
          if (!disposed) {
            void applySnapshot(next, true);
          }
        })
        .catch(() => {
          // best-effort startup reconcile so offline lock/unlock changes
          // are pulled into UI when the runtime comes back online.
        });
    }, 600);

    return () => {
      disposed = true;
      window.clearTimeout(timer);
    };
  }, [runtime?.running, runtime?.started_at, runtime?.mode, activeAgentName]);

  const activeConversationLastSeq = useMemo(() => {
    if (!activeConversation?.messages?.length) return 0;
    return activeConversation.messages[activeConversation.messages.length - 1]?.seq || 0;
  }, [activeConversation, renderEpoch]);

  useEffect(() => {
    snapshotRef.current = snapshot;
  }, [snapshot]);

  useEffect(() => {
    if (agentType !== "ai") return;
    if (aiProvider !== "ollama") return;
    void refreshAiProviderCatalog().catch((err) => {
      setUiFeedback(String(err), true);
    });
  }, [agentType, aiProvider]);

  useEffect(() => {
    setAiProviderApiKeyInput("");
    if (agentType !== "ai" || !providerNeedsApiKey(aiProvider)) {
      setAiProviderSecretStatus(null);
      return;
    }
    void refreshAiProviderSecretStatus(aiProvider).catch((err) => {
      setUiFeedback(String(err), true);
    });
  }, [agentType, aiProvider]);

  useEffect(() => {
    if (agentType !== "ai") {
      setAgentSkills([]);
      resetAgentSkillEditor();
      return;
    }
    void refreshAgentSkills(agentName.trim()).catch((err) => {
      setUiFeedback(String(err), true);
    });
  }, [agentType, agentName]);

  useEffect(() => {
    const needsOllamaStatus = sortedAgentCards.some(
      (agent) =>
        normalizeAgentType(agent.agent_type) === "ai" &&
        String(agent.ai_provider || "").trim().toLowerCase() === "ollama"
    );
    if (!needsOllamaStatus || ollamaCatalogLoading || ollamaCatalog) {
      return;
    }
    void refreshAiProviderCatalog().catch(() => {
      // best-effort status hydration for AI cards
    });
  }, [sortedAgentCards, ollamaCatalog, ollamaCatalogLoading]);

  useEffect(() => {
    const providers = new Set<AiProviderKind>();
    for (const agent of sortedAgentCards) {
      if (normalizeAgentType(agent.agent_type) !== "ai") continue;
      const provider = String(agent.ai_provider || "").trim().toLowerCase();
      if (!providerNeedsApiKey(provider)) continue;
      if (
        provider === "openai" ||
        provider === "claude" ||
        provider === "gemini"
      ) {
        providers.add(provider as AiProviderKind);
      }
    }
    for (const provider of providers) {
      if (aiProviderSecretStatusCache[provider]) continue;
      void refreshAiProviderSecretStatus(provider).catch(() => {
        // best-effort provider status hydration for AI cards
      });
    }
  }, [sortedAgentCards, aiProviderSecretStatusCache]);

  useEffect(() => {
    const node = chatThreadRef.current;
    if (!node) return;
    if (!forceScrollToBottomRef.current && !stickToBottomRef.current) return;
    window.requestAnimationFrame(() => {
      if (chatThreadRef.current) {
        chatThreadRef.current.scrollTop = chatThreadRef.current.scrollHeight;
      }
      forceScrollToBottomRef.current = false;
    });
  }, [
    activeConversationKey,
    activeConversationLastSeq,
    pendingIncomingTransferOffersForActiveDid.length,
    pendingGroupOffersForActiveGroup.length
  ]);

  useEffect(() => {
    const nextMode = logModeForTransport(transport, logMode);
    if (nextMode !== logMode) {
      setLogMode(nextMode as LogMode);
      return;
    }
    setConfigPath(ensureDerivedConfigPath(agentName, nextMode as LogMode));
  }, [agentName, logMode, transport]);

  useEffect(() => {
    let disposed = false;
    let timer: number | undefined;

    const loop = async () => {
      if (disposed) return;
      timer = window.setTimeout(loop, currentPollIntervalMs());
      if (refreshInFlightRef.current) return;
      refreshInFlightRef.current = true;
      try {
        await refreshSnapshot(true);
      } catch (err) {
        setUiFeedback(String(err), true);
      } finally {
        refreshInFlightRef.current = false;
      }
    };

    // Resolve workspace root from Rust backend (platform-aware)
    void invoke<string>("get_workspace_root").then((root) => {
      if (root) workspaceRoot = root;
    }).catch(() => {
      // Fallback: workspace root stays as default
    });

    void scrubBrowserResidue();
    timer = window.setTimeout(loop, 200);

    const onBeforeUnload = () => {
      clearSensitiveUiMemory();
    };
    window.addEventListener("beforeunload", onBeforeUnload);

    return () => {
      disposed = true;
      if (timer) window.clearTimeout(timer);
      window.removeEventListener("beforeunload", onBeforeUnload);
      clearSensitiveUiMemory();
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    let unlistenTransfer: (() => void) | null = null;
    let unlistenGhost: (() => void) | null = null;
    let unlistenGroup: (() => void) | null = null;

    const scheduleFastRefresh = () => {
      if (disposed) return;
      if (eventRefreshTimerRef.current) {
        window.clearTimeout(eventRefreshTimerRef.current);
      }
      eventRefreshTimerRef.current = window.setTimeout(async () => {
        eventRefreshTimerRef.current = null;
        if (refreshInFlightRef.current) return;
        refreshInFlightRef.current = true;
        try {
          await refreshSnapshot(true);
        } catch {
          // best-effort refresh on runtime line event
        } finally {
          refreshInFlightRef.current = false;
        }
      }, 24);
    };

    void listen<RuntimeLineEvent>("qypha://runtime-line", (_event) => {
      scheduleFastRefresh();
    })
      .then((off) => {
        if (disposed) {
          off();
          return;
        }
        unlisten = off;
      })
      .catch(() => {
        // best-effort
      });

    void listen<TransferRuntimeEvent>("qypha://transfer-event", (event) => {
      scheduleFastRefresh();
      applyGhostTransferEvent(event.payload);
      const feedbackPayload = transferEventFeedback(event.payload);
      if (feedbackPayload) {
        setUiFeedback(feedbackPayload.text, feedbackPayload.isError);
      }
    })
      .then((off) => {
        if (disposed) {
          off();
          return;
        }
        unlistenTransfer = off;
      })
      .catch(() => {
        // best-effort
      });

    void listen<GhostRuntimeEvent>("qypha://ghost-event", (event) => {
      scheduleFastRefresh();
      if (event.payload.event === "invite_code" && event.payload.kind && event.payload.code) {
        if (event.payload.agent === (snapshotRef.current?.active_agent || null)) {
          if (event.payload.kind === "group") {
            setLatestGroupInviteCode(event.payload.code);
          } else {
            setLatestInviteCode(event.payload.code);
          }
          forceRender();
        }
      }
    })
      .then((off) => {
        if (disposed) {
          off();
          return;
        }
        unlistenGhost = off;
      })
      .catch(() => {
        // best-effort
      });

    void listen<NamedGroupMailboxRuntimeEvent>("qypha://group-event", (event) => {
      scheduleFastRefresh();
      const next = mergeSnapshotGroupEvent(snapshotRef.current, event.payload);
      if (!next || next === snapshotRef.current || refreshInFlightRef.current) {
        return;
      }
      void applySnapshot(next, true);
    })
      .then((off) => {
        if (disposed) {
          off();
          return;
        }
        unlistenGroup = off;
      })
      .catch(() => {
        // best-effort
      });

    return () => {
      disposed = true;
      if (eventRefreshTimerRef.current) {
        window.clearTimeout(eventRefreshTimerRef.current);
        eventRefreshTimerRef.current = null;
      }
      if (unlisten) {
        unlisten();
      }
      if (unlistenTransfer) {
        unlistenTransfer();
      }
      if (unlistenGhost) {
        unlistenGhost();
      }
      if (unlistenGroup) {
        unlistenGroup();
      }
    };
  }, []);

  useEffect(() => {
    setComposerMenuOpen(false);
  }, [activeAgentName, activeConversationKey]);

  const receiveDirRef = useRef<string | null>(null);
  useEffect(() => {
    if (receiveDirSaved) return;
    const explicitDir = runtime?.receive_dir?.trim() || "";
    if (!explicitDir) return;
    if (explicitDir !== receiveDirRef.current) {
      receiveDirRef.current = explicitDir;
      setReceiveDirInput(explicitDir);
    }
  }, [runtime?.receive_dir, receiveDirSaved]);

  const runtimeMeta = useMemo(() => {
    const agent = snapshot?.agents.find((a) => a.name === snapshot.active_agent) || null;
    if (!agent) return "No active agent selected";
    const agentTypeLabel = normalizeAgentType(agent.agent_type) === "ai" ? "ai" : "human";
    if (agentTypeLabel === "ai") {
      const provider = providerLabel(agent.ai_provider);
      const model = agent.ai_model?.trim() ? ` • ${agent.ai_model.trim()}` : "";
      return `${agent.name} • ai • ${provider}${model} • ${aiRoleLabel(agent.ai_role)} • ${aiAccessModeLabel(agent.ai_access_mode)}`;
    }
    const online = runtime?.running ? "online" : "offline";
    const mode = runtime?.mode || agent.mode;
    const tr = runtime?.transport || agent.transport;
    const port = runtime?.listen_port || agent.listen_port;
    const peers = panelPeers.length;
    return `${agent.name} • ${agentTypeLabel} • ${mode} • ${transportLabel(tr)} • :${port} • ${online} • peers ${peers}`;
  }, [snapshot, runtime, panelPeers]);
  function resolveAiProviderRuntimeSummary(
    provider: string | null | undefined,
    secretStatus: AiProviderSecretStatus | null
  ): { title: string; primary: string; secondary: string; ok: boolean | null } | null {
    const normalizedProvider = String(provider || "").trim().toLowerCase();
    if (!normalizedProvider) return null;
    if (normalizedProvider === "ollama") {
      const discoveredCount = ollamaCatalog?.ollama_models?.length || 0;
      if (ollamaCatalogLoading && !ollamaCatalog) {
        return {
          title: "Runtime status",
          primary: "Checking Ollama host",
          secondary: "Waiting for the local Ollama catalog before marking this provider ready to launch.",
          ok: null,
        };
      }
      const available = !!ollamaCatalog?.ollama_available;
      return {
        title: "Runtime status",
        primary: available ? "Ready to start" : "Runtime blocked",
        secondary: available
          ? `Host ${ollamaCatalog?.ollama_host || "http://127.0.0.1:11434"} • ${discoveredCount} discovered model${discoveredCount === 1 ? "" : "s"}`
          : `Ollama host ${ollamaCatalog?.ollama_host || "http://127.0.0.1:11434"} is unreachable from the desktop app.`,
        ok: available,
      };
    }
    if (!secretStatus) {
      return {
        title: "Runtime status",
        primary: "Profile status pending",
        secondary: `Checking secure storage for ${providerLabel(normalizedProvider)} credentials.`,
        ok: null,
      };
    }
    if (secretStatus.configured) {
      return {
        title: "Runtime status",
        primary: "Ready to start",
        secondary: `${providerLabel(normalizedProvider)} credentials are stored in ${secretStatus.storage_label}. Start Agent will launch the full Qypha AI runtime with this provider.`,
        ok: true,
      };
    }
    return {
      title: "Runtime status",
      primary: "API key missing",
      secondary: `${providerLabel(normalizedProvider)} needs a secure API key before this profile can start.`,
      ok: false,
    };
  }

  const isCreatePending = runtimeActionPending === "create";
  const isStartPending = runtimeActionPending === "start";
  const isStopPending = runtimeActionPending === "stop";
  const selectedRuntimeIsRunning =
    !!runtime?.running && !!agentName.trim() && activeAgentName === agentName.trim();
  const startButtonDisabled = !agentName.trim() || selectedRuntimeIsRunning || !!runtimeActionPending;
  const startButtonLabel = isStartPending ? "Starting..." : agentType === "ai" ? "Start Agent" : "Start";

  function aiAgentCardStatusMeta(agent: AgentCard): { text: string; tone: "ok" | "warn" | "subtle" } | null {
    if (normalizeAgentType(agent.agent_type) !== "ai") return null;
    const provider = String(agent.ai_provider || "").trim().toLowerCase();
    if (!provider) return null;
    const summary = resolveAiProviderRuntimeSummary(provider, aiProviderSecretStatusCache[provider] || null);
    if (!summary) return null;
    return {
      text: summary.primary.toLowerCase(),
      tone: providerStatusTone(summary.ok),
    };
  }

  function incomingInviteLockMeta(
    agent: AgentCard
  ): {
    label: string;
    tone: "ok" | "warn" | "subtle";
    locked: boolean;
    actionable: boolean;
  } {
    if (!agent.running) {
      return { label: "offline", tone: "subtle", locked: false, actionable: false };
    }
    if (!agent.incoming_connect_policy_known) {
      return { label: "loading", tone: "subtle", locked: false, actionable: false };
    }
    if (agent.incoming_connect_block_all) {
      return { label: "locked", tone: "warn", locked: true, actionable: true };
    }
    return { label: "unlocked", tone: "ok", locked: false, actionable: true };
  }

  function renderAgentCollection(
    title: string,
    agentCards: AgentCard[],
    emptyLabel: string,
    description: string
  ) {
    return (
      <section className="agent-collection">
        <div className="agent-collection-head">
          <div>
            <h3>{title}</h3>
            <p className="muted">{description}</p>
          </div>
          <span className="agent-collection-count">{agentCards.length}</span>
        </div>
        <div className="agent-list-scroll agent-collection-scroll">
          <ul className="agent-list compact">
            {!agentCards.length && <li className="muted agent-list-empty">{emptyLabel}</li>}
            {agentCards.map((agent) => {
              const online = agent.running ? "online" : "offline";
              const selected = snapshot?.active_agent === agent.name;
              const modeLabel = agent.mode === "unknown" ? "unconfigured" : agent.mode;
              const agentTransportLabel = transportLabel(agent.transport);
              const portLabel = agent.listen_port > 0 ? `:${agent.listen_port}` : "no port";
              const agentTypeLabel = normalizeAgentType(agent.agent_type) === "ai" ? "ai" : "human";
              const providerHealth = aiAgentCardStatusMeta(agent);
              const providerSummary =
                agentTypeLabel === "ai"
                  ? `${providerLabel(agent.ai_provider)}${agent.ai_model ? ` • ${agent.ai_model}` : ""} • ${aiRoleLabel(agent.ai_role)} • ${aiAccessModeLabel(agent.ai_access_mode)} • ${transportLabel(agent.transport)} • ${agent.mode} • :${agent.listen_port}`
                  : null;
              const incomingInviteLock = incomingInviteLockMeta(agent);
              return (
                <li key={agent.name} className={`agent-item compact ${selected ? "active" : ""}`}>
                  <button className="agent-btn" onClick={() => void safeAction(() => selectAgent(agent.name))}>
                    <div className="agent-top">
                      <strong>{agent.name}</strong>
                      <div className="agent-top-meta">
                        <span className={`invite-pill ${incomingInviteLock.tone}`}>
                          inv {incomingInviteLock.label}
                        </span>
                        <span className={`status-pill ${online}`}>{online}</span>
                      </div>
                    </div>
                    <small>
                      {agentTypeLabel}
                      {agentTypeLabel === "human"
                        ? ` • ${modeLabel} • ${agentTransportLabel} • ${portLabel}`
                        : providerSummary
                          ? ` • ${providerSummary} • profile`
                          : " • profile"}
                    </small>
                    {normalizeAgentType(agent.agent_type) === "human" && !agent.config_present && (
                      <small className="muted">config missing • recreated on next start</small>
                    )}
                    {agentTypeLabel === "ai" && providerHealth && (
                      <small className={`agent-provider-health ${providerHealth.tone}`}>
                        {providerHealth.text}
                      </small>
                    )}
                  </button>
                  <div className="agent-card-actions">
                    <button
                      className={`btn mini ${incomingInviteLock.locked ? "" : "danger"} agent-invite-lock-btn`}
                      disabled={!incomingInviteLock.actionable}
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        void safeAction(() =>
                          setAgentIncomingConnectBlockAll(agent.name, !incomingInviteLock.locked)
                        );
                      }}
                    >
                      {incomingInviteLock.locked ? "Unlock Inv" : "Lock Inv"}
                    </button>
                    <button
                      className="btn mini danger agent-delete-btn"
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setPendingAgentDestroy({ mode: "single", agentName: agent.name });
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      </section>
    );
  }

  const selectedAgentSkill =
    agentSkills.find((skill) => skill.id === selectedAgentSkillId) || null;
  const aiSkillsCard =
    agentType === "ai" ? (
      <article className="card big">
        <section className="ai-skills-panel detached">
          <div className="ai-skills-head">
            <div>
              <p className="invite-kicker">Agent Skills</p>
              <h3 className="ai-skills-title">Custom Skill Library</h3>
              <p className="muted ai-skills-sub">
                Add multiple agent-specific skills as real <code>SKILL.md</code> files. These live only under this AI agent and are wiped when the agent is destroyed.
              </p>
            </div>
            <div className="invite-surface-meta">
              <span className="invite-pill">{agentName.trim() || "Set agent name"}</span>
              <span className="invite-pill subtle">
                {agentSkillsLoading ? "loading" : `${agentSkills.length} skill${agentSkills.length === 1 ? "" : "s"}`}
              </span>
            </div>
          </div>

          {!agentName.trim() ? (
            <div className="ai-skills-empty">
              <strong>Name the AI agent first</strong>
              <small>Once the agent has a name, you can attach any number of custom skills to it.</small>
            </div>
          ) : (
            <div className="ai-skills-layout">
              <div className="ai-skills-library">
                <div className="ai-skills-library-head">
                  <strong>Saved Skills</strong>
                  <button className="btn mini" onClick={resetAgentSkillEditor}>
                    New Skill
                  </button>
                </div>
                <div className="ai-skills-list">
                  {!agentSkills.length && (
                    <div className="ai-skills-empty">
                      <strong>No custom skills yet</strong>
                      <small>Create one below and it will be available to this agent as a real skill file.</small>
                    </div>
                  )}
                  {agentSkills.map((skill) => (
                    <button
                      key={skill.id}
                      className={`ai-skill-item ${selectedAgentSkillId === skill.id ? "active" : ""}`}
                      onClick={() => applyAgentSkillToEditor(skill)}
                    >
                      <span className="ai-skill-item-name">{skill.name}</span>
                      <span className="ai-skill-item-meta">
                        Updated {new Date(skill.updated_at_ms || Date.now()).toLocaleString()}
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="ai-skills-editor">
                <label className="field">
                  Skill Name
                  <input
                    value={agentSkillNameInput}
                    onChange={(e) => setAgentSkillNameInput(e.target.value)}
                    placeholder="skill1, cv_writer, or any label you want"
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                  />
                </label>

                <label className="field">
                  Skill Markdown
                  <textarea
                    className="ai-skill-markdown"
                    value={agentSkillMarkdownInput}
                    onChange={(e) => setAgentSkillMarkdownInput(e.target.value)}
                    placeholder="Paste the skill instructions here. The desktop app will save them as SKILL.md for this AI agent."
                    rows={16}
                    spellCheck={false}
                  />
                </label>

                <div className="ai-skills-editor-meta">
                  <small className="muted">
                    {selectedAgentSkill
                      ? `Editing ${selectedAgentSkill.file_path}`
                      : "The app will save this as a real SKILL.md and derive a skill description from your text so the agent can discover when to use it."}
                  </small>
                </div>

                <div className="ai-skills-actions">
                  <button
                    className="btn primary"
                    disabled={agentSkillSaving || !agentName.trim() || !agentSkillNameInput.trim() || !agentSkillMarkdownInput.trim()}
                    onClick={() => void safeAction(saveAgentSkill)}
                  >
                    {agentSkillSaving ? "Saving..." : selectedAgentSkill ? "Update Skill" : "Save Skill"}
                  </button>
                  <button
                    className="btn"
                    disabled={agentSkillSaving}
                    onClick={resetAgentSkillEditor}
                  >
                    Clear
                  </button>
                  <button
                    className="btn danger"
                    disabled={!selectedAgentSkill || agentSkillDeletingId === selectedAgentSkill?.id}
                    onClick={() => void safeAction(deleteAgentSkill)}
                  >
                    {agentSkillDeletingId === selectedAgentSkill?.id ? "Deleting..." : "Delete Skill"}
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      </article>
    ) : null;

  const inviteHubCard = (
    <article className="card big">
      <section ref={inviteHubRef} className="invite-hub detached">
        <div className="invite-hub-head">
          <div>
            <p className="invite-kicker">Invite Hub</p>
            <h3 className="invite-hub-title">Agent + Group Access</h3>
            <p className="muted invite-hub-sub">
              Keep direct onboarding and mailbox group refreshes in one clean area. Group invites only unlock for rooms this agent owns.
            </p>
          </div>
          <div className="invite-hub-switch">
            <button
              className={`btn mini ${inviteHubSection === "direct" ? "primary" : ""}`}
              onClick={() => focusInviteHub("direct")}
            >
              Agent Invite
            </button>
            <button
              className={`btn mini ${inviteHubSection === "group" ? "primary" : ""}`}
              onClick={() =>
                focusInviteHub(
                  "group",
                  selectedInviteGroup?.group_id || orderedMailboxGroups[0]?.group_id || null
                )
              }
            >
              Group Management
            </button>
          </div>
        </div>

        <div className="invite-stage">
          {inviteHubSection === "direct" ? (
            <section className="invite-surface invite-stage-card">
              <div className="invite-stage-top">
                <div>
                  <h3 className="invite-surface-title">Agent Invite</h3>
                  <p className="muted invite-surface-sub">
                    Generate a fresh direct invite for the active agent and share it with a peer.
                  </p>
                </div>
                <div className="invite-surface-meta">
                  <span className="invite-pill">{activeAgentName || "No agent"}</span>
                  <span className="invite-pill subtle">{runtime?.running ? "Runtime live" : "Runtime offline"}</span>
                </div>
              </div>

              <div className="invite-inline-actions">
                <button className="btn mini primary" onClick={() => void safeAction(() => generateInvite("direct"))}>
                  Generate Invite
                </button>
                <button
                  className="btn mini"
                  disabled={isGhost}
                  onClick={() => void safeAction(() => copyTextWithPolicy(latestInviteCode, "Invite code"))}
                >
                  Copy invite
                </button>
              </div>

              <label className="invite-code-block invite-output">
                Latest agent invite
                <textarea
                  value={latestInviteCode}
                  readOnly
                  rows={6}
                  placeholder="Generate a fresh direct invite for this agent"
                />
              </label>
            </section>
          ) : (
            <section className="invite-surface invite-stage-card invite-group-surface">
              <div className="invite-stage-top invite-stage-top-group">
                <div>
                  <h3 className="invite-surface-title">Group Management</h3>
                  <p className="muted invite-surface-sub">
                    Create a new mailbox room, pick an existing one, and rotate fresh invites only when this agent owns the room.
                  </p>
                </div>
                <div className="invite-group-create">
                  <input
                    value={groupInviteName}
                    onChange={(e) => setGroupInviteName(e.target.value)}
                    placeholder={isGhost ? "Anonymous group name" : "New group name"}
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                  />
                  <button className="btn mini primary" onClick={() => void safeAction(() => generateInvite("group"))}>
                    {isGhost ? "Create Ghost Group" : "Create Group"}
                  </button>
                </div>
              </div>

              <div className="invite-group-layout">
                <aside className="invite-group-sidebar">
                  <p className="invite-group-sidebar-label">Groups</p>
                  <ul className="invite-group-list">
                    {!orderedMailboxGroups.length && <li className="muted">No mailbox groups yet.</li>}
                    {orderedMailboxGroups.map((group) => {
                      const ownerMode = isLocallyOwnedMailboxGroup(group);
                      const selected = selectedInviteGroup?.group_id === group.group_id;
                      return (
                        <li key={group.group_id}>
                          <button
                            className={`invite-group-btn ${selected ? "active" : ""}`}
                            onClick={() => {
                              setInviteHubSection("group");
                              setSelectedInviteGroupId(group.group_id);
                            }}
                          >
                            <div className="invite-group-line">
                              <strong>{mailboxGroupLabel(group)}</strong>
                              <div className="invite-group-tags">
                                <span className={`group-role-pill ${ownerMode ? "owner" : "member"}`}>
                                  {ownerMode ? "Owner" : "Member"}
                                </span>
                                <span className={`invite-pill ${mailboxGroupLockPillClass(group)}`}>
                                  {mailboxGroupLockLabel(group)}
                                </span>
                              </div>
                            </div>
                            <small className="invite-group-id" title={group.group_id}>{group.group_id}</small>
                            <small className="muted">
                              {group.anonymous_group ? "anonymous" : "identified"}
                              {group.anonymous_group && mailboxGroupAnonymousSecurityLabel(group)
                                ? ` • ${mailboxGroupAnonymousSecurityLabel(group)}`
                                : ""}
                              {" • "}epoch {group.mailbox_epoch}
                              {group.degraded ? " • degraded" : ""}
                            </small>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </aside>

                <div className="invite-group-detail">
                  {selectedInviteGroup ? (
                    <>
                      <div className="invite-group-detail-head">
                        <div>
                          <div className="invite-group-line invite-group-detail-line">
                            <h4 className="invite-group-detail-title">{mailboxGroupLabel(selectedInviteGroup)}</h4>
                            <div className="invite-group-tags">
                              <span className={`group-role-pill ${selectedInviteGroupIsOwner ? "owner" : "member"}`}>
                                {selectedInviteGroupIsOwner ? "Owner" : "Member"}
                              </span>
                              <span className={`invite-pill ${mailboxGroupLockPillClass(selectedInviteGroup)}`}>
                                {mailboxGroupLockLabel(selectedInviteGroup)}
                              </span>
                            </div>
                          </div>
                          <p className="muted invite-surface-sub">
                            {selectedInviteGroupIsOwner
                              ? selectedInviteGroup.anonymous_group
                                ? "This ghost room is owned by the active agent. Fresh invite rotation rekeys the room and invalidates older anonymous invites."
                                : "This room is owned by the active agent, so fresh invite rotation is available here."
                              : "This room was joined as a member, so fresh invite rotation stays hidden."}
                          </p>
                        </div>
                        <div className="invite-group-detail-actions">
                          <button className="btn mini" onClick={() => openMailboxGroupConversation(selectedInviteGroup)}>
                            Open conversation
                          </button>
                          <button
                            className="btn mini danger"
                            onClick={() =>
                              setPendingDelete({
                                agentName: activeAgentName,
                                key: groupConversationKey(selectedInviteGroup.group_id),
                                label: mailboxGroupLabel(selectedInviteGroup) || "this group",
                                did: null,
                                groupId: selectedInviteGroup.group_id,
                                mode: selectedInviteGroupIsOwner ? "group_disband" : "group_leave"
                              })
                            }
                          >
                            {selectedInviteGroupIsOwner ? "Disband Group" : "Leave Group"}
                          </button>
                          {selectedInviteGroupIsOwner && !selectedInviteGroup.anonymous_group && (
                            <button
                              className={`btn mini ${selectedInviteGroup.join_locked ? "" : "danger"}`}
                              onClick={() =>
                                void safeAction(
                                  () =>
                                    setMailboxGroupJoinLock(
                                      selectedInviteGroup,
                                      !selectedInviteGroup.join_locked
                                    )
                                )
                              }
                            >
                              {selectedInviteGroup.join_locked ? "Unlock Group" : "Lock Group"}
                            </button>
                          )}
                          {selectedInviteGroupIsOwner && (
                            <button
                              className="btn mini primary"
                              disabled={!!selectedInviteGroup.join_locked && !selectedInviteGroup.anonymous_group}
                              onClick={() =>
                                void safeAction(() =>
                                  regenerateMailboxGroupInvite(selectedInviteGroup.group_id)
                                )
                              }
                            >
                              {selectedInviteGroup.anonymous_group ? "Rotate Invite" : "Fresh Invite"}
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="invite-group-stats">
                        <span className="invite-pill">
                          {selectedInviteGroup.anonymous_group ? "anonymous" : "identified"}
                        </span>
                        {selectedInviteGroup.anonymous_group && (
                          <span
                            className={`invite-pill ${mailboxGroupAnonymousSecurityPillClass(
                              selectedInviteGroup
                            )}`}
                          >
                            {mailboxGroupAnonymousSecurityLabel(selectedInviteGroup) || "legacy"}
                          </span>
                        )}
                        <span className="invite-pill">{selectedInviteGroup.persistence}</span>
                        <span className={`invite-pill ${mailboxGroupLockPillClass(selectedInviteGroup)}`}>
                          {mailboxGroupLockLabel(selectedInviteGroup)}
                        </span>
                        <span className="invite-pill">epoch {selectedInviteGroup.mailbox_epoch}</span>
                        {selectedInviteGroup.degraded && <span className="invite-pill warn">Degraded</span>}
                      </div>

                      <label className="invite-code-block invite-output">
                        {selectedInviteGroupIsOwner
                          ? selectedInviteGroup.anonymous_group
                            ? "Rotated invite output"
                            : "Fresh invite output"
                          : "Invite output"}
                        <textarea
                          value={selectedInviteGroupInviteCode}
                          readOnly
                          rows={6}
                          placeholder={
                            selectedInviteGroupIsOwner
                              ? "Generate a fresh invite for the selected group"
                              : "Owner-only invite controls stay hidden for groups you did not create."
                          }
                        />
                      </label>
                      {selectedInviteGroup.anonymous_group && selectedInviteGroupIsOwner && (
                        <small className="muted invite-security-note">
                          {selectedInviteGroupRotationNotice
                            ? `Epoch rotated to ${selectedInviteGroupRotationNotice.currentEpoch}. Older ghost invites${
                                typeof selectedInviteGroupRotationNotice.previousEpoch === "number"
                                  ? ` from epoch ${selectedInviteGroupRotationNotice.previousEpoch}`
                                  : ""
                              } are now invalid and must not be shared.`
                            : "Fresh ghost invites are epoch-scoped. When you rotate an invite, older anonymous invites and writer credentials become invalid."}
                        </small>
                      )}

                      {selectedInviteGroupIsOwner && (
                        <div className="invite-inline-actions">
                          <button
                            className="btn mini"
                            disabled={isGhost || !selectedInviteGroupInviteCode}
                            onClick={() =>
                              void safeAction(() =>
                                copyTextWithPolicy(selectedInviteGroupInviteCode, "Group invite code")
                              )
                            }
                          >
                            Copy group invite
                          </button>
                        </div>
                      )}
                    </>
                  ) : pendingCreatedGroupInvite ? (
                    <>
                      <div className="invite-group-detail-head">
                        <div>
                          <h4 className="invite-group-detail-title">{pendingCreatedGroupInvite.groupName}</h4>
                          <p className="muted invite-surface-sub">
                            Group created. Invite code is ready now, and the room card will attach here as soon as the runtime snapshot finishes syncing.
                          </p>
                        </div>
                        <div className="invite-group-detail-actions">
                          <button
                            className="btn mini"
                            disabled={isGhost || !latestGroupInviteCode}
                            onClick={() =>
                              void safeAction(() =>
                                copyTextWithPolicy(latestGroupInviteCode, "Group invite code")
                              )
                            }
                          >
                            Copy group invite
                          </button>
                        </div>
                      </div>

                      <div className="invite-group-stats">
                        <span className="invite-pill">owner</span>
                        <span className="invite-pill subtle">syncing room state</span>
                      </div>

                      <label className="invite-code-block invite-output">
                        Fresh invite output
                        <textarea
                          value={latestGroupInviteCode}
                          readOnly
                          rows={6}
                          placeholder="Fresh group invite will appear here"
                        />
                      </label>
                    </>
                  ) : (
                    <div className="invite-empty-state">
                      <p>Select a mailbox group to manage invites, or create a new one here.</p>
                    </div>
                  )}
                </div>
              </div>

              <small className="muted invite-security-note">{inviteSecuritySummary}</small>

              {!!pendingHandshakeOffers.length && (
                <div className="invite-offers">
                  <strong>Pending trust offers</strong>
                  {pendingHandshakeOffers.map((offer, idx) => (
                    <div key={`${offer.group_id}:${offer.sender_member_id}:${idx}`} className="invite-offer-row">
                      <small className="muted">
                        Direct trust offer • {offer.group_name || offer.group_id} •{" "}
                        {maskDidForUi(offer.sender_member_id || "", maskDid)}
                      </small>
                      <div className="inline" style={{ gap: 8 }}>
                        <button
                          className="btn mini accept"
                          onClick={() => void safeAction(() => acceptGroupHandshakeOffer(offer.sender_member_id || ""))}
                        >
                          Accept
                        </button>
                        <button
                          className="btn mini danger"
                          onClick={() => void safeAction(() => rejectGroupHandshakeOffer(offer.sender_member_id || ""))}
                        >
                          Reject
                        </button>
                        <button
                          className="btn mini muted-btn"
                          onClick={() => void safeAction(() => blockGroupHandshakeOffer(offer.sender_member_id || ""))}
                        >
                          Block
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
        </div>
      </section>
    </article>
  );

  return (
    <div className="ql-root">
      <div className="bg-grid" />
      <div className="orb orb-1" />
      <div className="orb orb-2" />

      <main className="shell">
        <header className="topbar">
          <div className="brand">
            <img className="brand-logo" src="/qypha-logo.png" alt="Qypha logo" />
            <div>
            <h1>Qypha</h1>
            <p>A decentralized cryptographic network for humans and AI agents.</p>
            </div>
          </div>
          <div className="top-actions">
            <button className="btn mini" onClick={() => void safeAction(() => refreshSnapshot(true))}>
              Refresh
            </button>
          </div>
        </header>

        <section className="cards">
          <article className="card big">
            <h2>Runtime + Agent Setup</h2>
            <p className="muted setup-intro">
              Pick the agent you want to create, then configure only the fields that matter for that mode.
            </p>
            <div className="runtime-grid">
              <label className="field">
                Agent Name
                <input
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                />
              </label>

              <div className="field runtime-grid-full">
                Agent Type
                <div className="agent-mode-grid">
                  {(["human", "ai"] as AgentType[]).map((type) => (
                    <button
                      key={type}
                      className={`agent-mode-card ${agentType === type ? "active" : ""}`}
                      onClick={() => void handleAgentTypeSwitch(type)}
                    >
                      <strong>{agentTypeTitle(type)}</strong>
                      <span>{agentTypeDescription(type)}</span>
                    </button>
                  ))}
                </div>
              </div>

              {agentType === "ai" && (
                <label className="field">
                  Role
                  <div className="picker">
                    <button
                      className={`picker-btn ${aiRole === "general" ? "active" : ""}`}
                      onClick={() => setAiRole("general")}
                    >
                      General
                    </button>
                  </div>
                  <small className="muted">Initial AI role is fixed to general for now.</small>
                </label>
              )}

              {agentType === "ai" && (
                <label className="field">
                  LLM Type
                  <div className="picker">
                    {AI_PROVIDER_OPTIONS.map((provider) => (
                      <button
                        key={provider}
                        className={`picker-btn ${aiProvider === provider ? "active" : ""}`}
                        onClick={() => handleAiProviderSelect(provider)}
                      >
                        {providerLabel(provider)}
                      </button>
                    ))}
                  </div>
                </label>
              )}

              <label className="field">
                Transport
                <div className="picker">
                  {(["internet", "tor", "tcp"] as TransportMode[]).map((t) => (
                    <button
                      key={t}
                      className={`picker-btn ${transport === t ? "active" : ""}`}
                      onClick={() => setTransport(t)}
                    >
                      {transportLabel(t)}
                    </button>
                  ))}
                </div>
              </label>

              {showLogModePicker && (
                <label className="field">
                  Mode
                  <div className="picker">
                    {(["safe", "ghost"] as LogMode[]).map((m) => (
                      <button
                        key={m}
                        className={`picker-btn ${selectedLogMode === m ? "active" : ""}`}
                        onClick={() => setLogMode(m)}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </label>
              )}

              <label className="field">
                Listen Port
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={listenPortInput}
                  onChange={(e) => setListenPortInput(sanitizeListenPortInput(e.target.value))}
                  onBlur={() => setListenPort(resolveListenPort(listenPortInput, listenPort || 9090))}
                />
              </label>

              {(agentType === "human" || !isGhost) && (
                <>
              <label className="field">
                Passphrase (min 6 chars)
                <input
                  type="password"
                  value={passphrase}
                  disabled={isGhost}
                  onChange={(e) => setPassphrase(e.target.value)}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                />
              </label>
                </>
              )}

              {agentType === "ai" && aiProvider === "ollama" && (
                <label className="field">
                  Ollama Models
                  <div className="provider-status-inline">
                    <span className={`invite-pill ${ollamaCatalog?.ollama_available ? "ok" : "warn"}`}>
                      {ollamaCatalogLoading
                        ? "checking host"
                        : ollamaCatalog?.ollama_available
                          ? "host reachable"
                          : "host unreachable"}
                    </span>
                    <span className="invite-pill subtle">
                      {ollamaCatalog?.ollama_models?.length || 0} discovered model{(ollamaCatalog?.ollama_models?.length || 0) === 1 ? "" : "s"}
                    </span>
                  </div>
                  <div className="model-field-row">
                    <select
                      className="select-input"
                      value={aiModel}
                      onChange={(e) => setAiModel(e.target.value)}
                    >
                      <option value="">
                        {ollamaCatalogLoading
                          ? "Loading models..."
                          : ollamaCatalog?.ollama_models?.length
                            ? "Select an Ollama model"
                            : "No discovered models"}
                      </option>
                      {(ollamaCatalog?.ollama_models || []).map((model) => (
                        <option key={`${model.source}:${model.id}`} value={model.id}>
                          {model.label} {model.source === "cloud" ? "(cloud)" : "(local)"}
                        </option>
                      ))}
                    </select>
                    <button
                      className="btn mini"
                      onClick={() => void safeAction(refreshAiProviderCatalog)}
                      disabled={ollamaCatalogLoading}
                    >
                      {ollamaCatalogLoading ? "Loading" : "Refresh"}
                    </button>
                  </div>
                  <input
                    value={aiModel}
                    onChange={(e) => setAiModel(e.target.value)}
                    placeholder="ollama model name"
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                  />
                  <small className="muted">
                    Host: {ollamaCatalog?.ollama_host || "http://127.0.0.1:11434"}
                    {ollamaCatalog?.ollama_error ? ` • ${ollamaCatalog.ollama_error}` : ""}
                  </small>
                </label>
              )}

              {agentType === "ai" && aiProvider !== "ollama" && (
                <>
                  <label className="field">
                    Model
                    <small className="muted">
                      Default: {providerDefaultModelLabel(aiProvider) || providerLabel(aiProvider)} • API id{" "}
                      {providerDefaultModelId(aiProvider) || "custom"}
                    </small>
                    <input
                      value={aiModel}
                      onChange={(e) => setAiModel(e.target.value)}
                      placeholder={providerDefaultModelId(aiProvider) || `${providerLabel(aiProvider)} model id`}
                      autoComplete="off"
                      autoCorrect="off"
                      autoCapitalize="off"
                      spellCheck={false}
                    />
                  </label>

                  <label className="field">
                    Provider API Key
                    <div className="provider-secret-row">
                      <input
                        type="text"
                        value={aiProviderApiKeyInput}
                        onChange={(e) => setAiProviderApiKeyInput(e.target.value)}
                        placeholder={providerApiKeyPlaceholder(aiProvider)}
                        autoComplete="off"
                        autoCorrect="off"
                        autoCapitalize="off"
                        spellCheck={false}
                      />
                      <button
                        className="btn mini"
                        disabled={aiProviderSecretSaving || !aiProviderApiKeyInput.trim()}
                        onClick={() => void safeAction(saveAiProviderSecret)}
                      >
                        {aiProviderSecretSaving ? "Saving" : "Save"}
                      </button>
                      <button
                        className="btn mini danger"
                        disabled={aiProviderSecretSaving || !aiProviderSecretStatus?.configured}
                        onClick={() => void safeAction(deleteAiProviderSecret)}
                      >
                        Remove
                      </button>
                    </div>
                    <small className="muted">
                      Paste the full key directly here, then save it to secure storage.
                      {" "}
                      {aiProviderSecretLoading
                        ? "Checking secure storage..."
                        : aiProviderSecretStatus?.configured
                          ? `${providerLabel(aiProvider)} credential is configured in ${aiProviderSecretStatus.storage_label}.`
                          : `${providerLabel(aiProvider)} credential is not stored yet.`}
                      {aiProviderSecretStatus?.env_var_hint
                        ? ` • Runtime env hint: ${aiProviderSecretStatus.env_var_hint}`
                        : ""}
                    </small>
                  </label>
                </>
              )}

            </div>

            <div className={`config-panel ${showConfigPanel ? "" : "hidden"}`}>
              <p className="muted">Generated config (safe mode, sensitive fields encrypted at rest)</p>
              <code>{configPath || "(ghost mode: no persistent config)"}</code>
            </div>

            {agentType === "human" && (
            <div className="receive-dir-panel">
              <label className="field-label">
                Receive Directory
                <div className="receive-dir-row">
                  <input
                    type="text"
                    value={receiveDirInput}
                    placeholder="~/Desktop/received/"
                    onChange={(e) => { setReceiveDirInput(e.target.value); setReceiveDirSaved(false); }}
                    disabled={!runtime?.running}
                    autoComplete="off"
                    spellCheck={false}
                    className="receive-dir-input"
                  />
                  <button
                    className="btn mini"
                    disabled={!runtime?.running || receiveDirSaved}
                    onClick={() => {
                      void safeAction(async () => {
                        const path = receiveDirInput.trim();
                        const resolved = await invokeOrThrow<string>("set_receive_dir", {
                          path: path || "reset"
                        });
                        setReceiveDirInput(resolved.trim());
                        setReceiveDirSaved(true);
                        setUiFeedback(
                          path ? `Receive dir: ${resolved.trim()}` : `Receive dir reset to ${resolved.trim()}`,
                          false
                        );
                        setTimeout(() => setReceiveDirSaved(false), 2000);
                      });
                    }}
                  >
                    {receiveDirSaved ? "Saved" : "Save"}
                  </button>
                </div>
                <small className="muted">
                  Leave empty for default: ~/Desktop/received/
                  {isGhost ? " • ghost session override applies only to the current session and is used on export" : ""}
                </small>
              </label>
            </div>
            )}

            <div className="runtime-actions">
              {agentType === "human" && (
                <button
                  className="btn"
                  disabled={isGhost || !!runtimeActionPending}
                  onClick={() => void runRuntimeAction("create", createAgent, "Creating agent...")}
                >
                  {isCreatePending ? "Creating..." : "Create Agent"}
                </button>
              )}
              <button
                className={`btn ${startButtonDisabled ? "disabled" : "primary"}`}
                disabled={startButtonDisabled}
                onClick={() =>
                  void runRuntimeAction(
                    "start",
                    startRuntime,
                    agentType === "ai" ? "Starting AI agent..." : "Starting agent..."
                  )
                }
              >
                {startButtonLabel}
              </button>
              <button
                className={`btn danger ${runtime?.running && !runtimeActionPending ? "" : "disabled"}`}
                disabled={!runtime?.running || !!runtimeActionPending}
                onClick={() => void runRuntimeAction("stop", stopRuntime, "Stopping agent...")}
              >
                {isStopPending ? "Stopping..." : "Stop"}
              </button>
            </div>

            {agentType === "ai" && (
              <p className="muted ghost-hint">
                AI agent: role `general`, access `full access`. Start Agent saves provider, transport, mode, and port settings, then launches the same Qypha AI runtime flow used by the terminal wizard. Safe mode requires a passphrase; Ghost mode is Tor-only and memory-only.
              </p>
            )}
            {agentType === "human" && isGhost && (
              <p className="muted ghost-hint">
                Ghost mode: Tor zorunlu, config/passphrase/create-agent kapalıdır. Session memory-only tutulur.
              </p>
            )}
            {agentType === "human" && !isGhost && !runtime?.running && (
              <p className="muted ghost-hint">
                Start auto-creates the agent. Passphrase (min 6 chars) is required.
              </p>
            )}

            <p className="muted runtime-meta">{runtimeMeta}</p>

            <div className="security-rail">
              <label className="inline-check">
                <input type="checkbox" checked={maskDid} onChange={(e) => setMaskDid(e.target.checked)} />
                Mask DID in UI
              </label>
            </div>

            <p className={`muted feedback ${feedbackError ? "error" : ""}`}>{feedback}</p>
          </article>

          <article className="card">
            <div className="card-head">
              <div>
                <h2>Local Agents</h2>
                <p className="muted card-head-sub">{sortedAgentCards.length || 0} registered</p>
              </div>
              <button
                className="btn mini danger"
                disabled={!sortedAgentCards.length}
                onClick={() => setPendingAgentDestroy({ mode: "all", agentName: null })}
              >
                Delete all
              </button>
            </div>
            <div className="agent-collection-grid">
              {renderAgentCollection(
                "Human Agents",
                humanAgentCards,
                "No human agents created yet.",
                "Networked agents with transport, runtime mode, and receive-directory controls."
              )}
              {renderAgentCollection(
                "AI Agents",
                aiAgentCards,
                "No AI agents created yet.",
                "Provider-backed assistants with model, role, and access-profile metadata."
              )}
            </div>
          </article>

          <article className="card">
            <div className="card-head">
              <div>
                <h2>Peers</h2>
                <p className="card-head-sub muted">
                  {pendingContactRequests.length
                    ? `${pendingContactRequests.length} incoming DID request${pendingContactRequests.length === 1 ? "" : "s"} shown at the top.`
                    : "Known peers and direct contact requests."}
                </p>
              </div>
            </div>
            <ul className="peer-list">
              {!pendingContactRequests.length && !panelPeers.length && <li className="muted">No known peers yet</li>}
              {pendingContactRequests.map((request) => {
                const requestDid = String(request.contact_did || request.did || "").trim();
                const requestName = cleanPeerName(request.name, requestDid || request.did);
                const requestBusy = contactRequestActionDid === requestDid;
                return (
                  <li key={`pending:${requestDid || request.did}`} className="peer-item peer-item-pending">
                    <div>
                      <strong>{requestName}</strong>
                      <small>{maskDidForUi(requestDid || request.did, maskDid)}</small>
                      <small className="muted">Incoming DID contact request</small>
                    </div>
                    <div className="peer-actions">
                      <button
                        className="btn mini accept"
                        disabled={requestBusy}
                        onClick={() => void safeAction(() => applyIncomingContactDecision("accept", requestDid || request.did))}
                      >
                        {requestBusy ? "Working..." : "Accept"}
                      </button>
                      <button
                        className="btn mini danger"
                        disabled={requestBusy}
                        onClick={() => void safeAction(() => applyIncomingContactDecision("reject", requestDid || request.did))}
                      >
                        Reject
                      </button>
                    </div>
                  </li>
                );
              })}
              {panelPeers.map((peer) => {
                return (
                  <li key={peer.did} className="peer-item">
                    <div>
                      <strong>{cleanPeerName(peer.name, peer.did)}</strong>
                      <small>{maskDidForUi(visibleDidForPeer(peer), maskDid)}</small>
                      <small className="muted">{peer.status}</small>
                    </div>
                    <div className="peer-actions">
                      <button
                        className="btn mini danger"
                        title="Bu kullanıcıyla bağlantıyı kapat ve eşleşmeyi kaldır"
                        onClick={() =>
                          setPendingDelete({
                            agentName: activeAgentName,
                            key: `dm:${peer.did}`,
                            label: cleanPeerName(peer.name, peer.did),
                            did: peer.did,
                            mode: "disconnect"
                          })
                        }
                      >
                        Disconnect
                      </button>
                      <button
                        className="btn mini"
                        disabled={activeAgentIsAi}
                        onClick={() => {
                          forceScrollToBottomRef.current = true;
                          clearConversationDeleted(activeAgentName, peer.did);
                          const map = conversationMapForAgent(activeAgentName);
                          const key = `dm:${peer.did}`;
                          if (!map.has(key)) {
                            ensureConversation(map, key, "dm", cleanPeerName(peer.name, peer.did), peer.did, true);
                          } else {
                            ensureConversation(map, key, "dm", cleanPeerName(peer.name, peer.did), peer.did, true);
                          }
                          setSelectedPeerForAgent(activeAgentName, peer.did);
                          setActiveConversationKey(activeAgentName, key);
                          forceRender();
                          void invokeOrThrow<void>("runtime_set_selected_peer", { peer: peer.did }).catch((err) =>
                            setUiFeedback(String(err), true)
                          );
                        }}
                        title={activeAgentIsAi ? "AI agents handle peers autonomously; use the control chat instead" : "Open direct chat"}
                      >
                        {activeAgentIsAi ? "Agent-controlled" : "Open DM"}
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          </article>

          <article ref={conversationsCardRef} className="card big">
            <h2>{activeAgentIsAi ? "Agent Control" : "Conversations"}</h2>
            <div className="chat-layout">
              <aside className="chat-sidebar">
                <div className="chat-sidebar-top">
                  <p>{activeAgentIsAi ? "Control Chat" : "Chats"}</p>
                  <input
                    value={conversationFilter}
                    onChange={(e) => setConversationFilter(e.target.value)}
                    placeholder={activeAgentIsAi ? "Search control history" : "Search chats"}
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                  />
                </div>
                <ul className="conversation-list">
                  {!orderedConversations.length && <li className="muted">No conversations</li>}
                  {orderedConversations.map((conv) => {
                    const isDm = conv.type === "dm";
                    const groupId = groupIdFromConversationKey(conv.key);
                    const isAiConversation = isLocalAiDid(conv.did);
                    const isOnline = isDm ? (isAiConversation || onlineDidSet.has(conv.did || "")) : false;
                    const selected = conv.key === activeConversationKey;
                    const preview = conv.messages.length
                      ? conv.messages[conv.messages.length - 1].text
                      : (conv.type === "group" ? "group conversation" : "direct conversation");
                    const avatarSeed = (conv.title || "Q").slice(0, 1).toUpperCase();
                    const conversationGroup =
                      !isDm && groupId
                        ? mailboxGroups(runtime).find((group) => group.group_id === groupId) || null
                        : null;
                    const canDisbandGroup = !!conversationGroup && isLocallyOwnedMailboxGroup(conversationGroup);
                    return (
                      <li key={conv.key} className="conversation-item">
                        <div className="conversation-row">
                          <button
                            className={`conversation-btn ${selected ? "selected" : ""}`}
                            onClick={() => {
                              forceScrollToBottomRef.current = true;
                              setActiveConversationKey(activeAgentName, conv.key);
                              if (conv.type === "dm" && conv.did && !isLocalAiDid(conv.did)) {
                                clearConversationDeleted(activeAgentName, conv.did);
                                setSelectedPeerForAgent(activeAgentName, conv.did);
                                void invokeOrThrow<void>("runtime_set_selected_peer", { peer: conv.did }).catch((err) =>
                                  setUiFeedback(String(err), true)
                                );
                              } else if (conv.type === "dm" && conv.did && isLocalAiDid(conv.did)) {
                                setSelectedPeerForAgent(activeAgentName, null);
                                setSelectedGroupForAgent(activeAgentName, null);
                                const aiTarget = aiAgentNameFromDid(conv.did);
                                if (aiTarget) {
                                  void hydrateAiConversation(activeAgentName, aiTarget).catch((err) =>
                                    setUiFeedback(String(err), true)
                                  );
                                }
                              } else {
                                setSelectedPeerForAgent(activeAgentName, null);
                                setSelectedGroupForAgent(activeAgentName, groupIdFromConversationKey(conv.key));
                              }
                              forceRender();
                            }}
                          >
                            <div className="conversation-content">
                              <div className={`conversation-avatar ${isDm ? (isOnline ? "online" : "offline") : "group"}`}>
                                {conv.type === "group" ? "G" : avatarSeed}
                              </div>
                              <div className="conversation-meta">
                                <div className="conversation-head">
                                  <span className={`conversation-name ${isDm ? (isOnline ? "online" : "offline") : ""}`}>
                                    {isDm ? cleanPeerName(conv.title, conv.did || undefined) : conv.title}{" "}
                                    {isDm && (
                                      <span className={`conversation-inline-state ${isOnline ? "online" : "offline"}`}>
                                        {isAiConversation ? "(ai)" : isOnline ? "(online)" : "(offline)"}
                                      </span>
                                    )}
                                  </span>
                                </div>
                                <small className="conversation-preview">{preview}</small>
                                <small className="conversation-address">
                                  {isDm
                                    ? isAiConversation
                                      ? `${providerLabel(
                                          (snapshot?.agents.find((agent) => agent.name === aiAgentNameFromDid(conv.did)) || null)
                                            ?.ai_provider
                                        )} • ${aiRoleLabel(
                                          (snapshot?.agents.find((agent) => agent.name === aiAgentNameFromDid(conv.did)) || null)
                                            ?.ai_role
                                        )}`
                                      : maskDidForUi(visibleDidForRuntimeDid(runtime, conv.did), maskDid)
                                    : (groupId || "group")}
                                </small>
                              </div>
                            </div>
                          </button>

                          {isDm && !isAiConversation ? (
                            <div className="conversation-menu-wrap">
                              <button
                                className="conversation-menu-btn"
                                onClick={(e) => {
                                  e.preventDefault();
                                  e.stopPropagation();
                                  setOpenConversationMenuKey((prev) => (prev === conv.key ? null : conv.key));
                                }}
                              >
                                ⋯
                              </button>
                              <div className={`conversation-menu ${openConversationMenuKey === conv.key ? "show" : ""}`}>
                                <button
                                  className="conversation-menu-item"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    setOpenConversationMenuKey(null);
                                    setPendingDelete({
                                      agentName: activeAgentName,
                                      key: conv.key,
                                      label: conv.title || "this conversation",
                                      did: conv.did || null,
                                      mode: "chat"
                                    });
                                  }}
                                >
                                  Delete chat
                                </button>
                                <button
                                  className="conversation-menu-item danger"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    setOpenConversationMenuKey(null);
                                    setPendingDelete({
                                      agentName: activeAgentName,
                                      key: conv.key,
                                      label: conv.title || "this conversation",
                                      did: conv.did || null,
                                      mode: "full"
                                    });
                                  }}
                                >
                                  Delete &amp; disconnect
                                </button>
                              </div>
                            </div>
                          ) : groupId ? (
                            <div className="conversation-menu-wrap">
                              <button
                                className="conversation-menu-btn"
                                onClick={(e) => {
                                  e.preventDefault();
                                  e.stopPropagation();
                                  setOpenConversationMenuKey((prev) => (prev === conv.key ? null : conv.key));
                                }}
                              >
                                ⋯
                              </button>
                              <div className={`conversation-menu ${openConversationMenuKey === conv.key ? "show" : ""}`}>
                                <button
                                  className="conversation-menu-item"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    setOpenConversationMenuKey(null);
                                    setPendingDelete({
                                      agentName: activeAgentName,
                                      key: conv.key,
                                      label: conv.title || "this group chat",
                                      did: null,
                                      groupId,
                                      mode: "group_chat"
                                    });
                                  }}
                                >
                                  Delete chat
                                </button>
                                {!!conversationGroup && (
                                  <button
                                    className="conversation-menu-item danger"
                                    onClick={(e) => {
                                      e.preventDefault();
                                      e.stopPropagation();
                                      setOpenConversationMenuKey(null);
                                      setPendingDelete({
                                        agentName: activeAgentName,
                                        key: conv.key,
                                        label: conv.title || "this group",
                                        did: null,
                                        groupId,
                                        mode: canDisbandGroup ? "group_disband" : "group_leave"
                                      });
                                    }}
                                  >
                                    {canDisbandGroup ? "Delete & Disband Group" : "Leave & Delete Group"}
                                  </button>
                                )}
                              </div>
                            </div>
                          ) : (
                            <span className="conversation-menu-spacer" />
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </aside>

              <section className="chat-main">
                <div className="chat-head">
                  <div className="chat-head-main">
                    <div className={`chat-head-avatar ${activeConversation?.type === "group" ? "group" : ""}`}>
                      {activeConversation?.type === "group"
                        ? "G"
                        : (activeConversation?.title?.slice(0, 1).toUpperCase() || "Q")}
                    </div>
                    <div>
                      <p className="chat-head-title">
                        {!activeConversation
                          ? "No active chat"
                          : activeConversation.type === "group"
                          ? activeConversationGroupLabel
                          : activeAiConversationAgent
                            ? `AI • ${activeAiConversationAgent}`
                          : cleanPeerName(activeConversation.title, activeConversation.did || undefined)}
                      </p>
                      <p className="muted selected-peer-label chat-head-sub">
                        {!activeConversation
                          ? "Select a conversation"
                          : activeConversation.type === "group"
                          ? (currentMailboxGroup
                              ? `${currentMailboxGroup.anonymous_group ? "anonymous" : "identified"} mailbox${
                                  currentMailboxGroup.anonymous_group &&
                                  mailboxGroupAnonymousSecurityLabel(currentMailboxGroup)
                                    ? ` • ${mailboxGroupAnonymousSecurityLabel(currentMailboxGroup)}`
                                    : ""
                                } • ${mailboxGroupLockLabel(currentMailboxGroup).toLowerCase()}${
                                  currentMailboxGroup.degraded ? " • degraded" : ""
                                } • epoch ${currentMailboxGroup.mailbox_epoch}`
                              : activeConversationGroupId
                                ? `${activeConversationGroupLabel} • syncing mailbox group state…`
                                : "select a mailbox group")
                          : activeAiConversationAgent
                            ? `${providerLabel(activeAiConversationCard?.ai_provider)}${
                                activeAiConversationCard?.ai_model ? ` • ${activeAiConversationCard.ai_model}` : ""
                              } • ${aiRoleLabel(activeAiConversationCard?.ai_role)} • ${aiAccessModeLabel(
                                activeAiConversationCard?.ai_access_mode
                              )}`
                          : maskDidForUi(visibleDidForRuntimeDid(runtime, activeConversation.did), maskDid)}
                        {activeConversation && !activeAiConversationAgent && runtime?.running && (
                          <span className="e2ee-badge">E2E Encrypted</span>
                        )}
                      </p>
                    </div>
                  </div>
                  {activeConversation?.type === "group" && (
                    <div className="chat-head-actions">
                      {currentMailboxGroup && (
                        <span className={`invite-pill ${mailboxGroupLockPillClass(currentMailboxGroup)}`}>
                          {mailboxGroupLockLabel(currentMailboxGroup)}
                        </span>
                      )}
                      {currentMailboxGroup?.anonymous_group && (
                        <span
                          className={`invite-pill ${mailboxGroupAnonymousSecurityPillClass(
                            currentMailboxGroup
                          )}`}
                        >
                          {mailboxGroupAnonymousSecurityLabel(currentMailboxGroup) || "legacy"}
                        </span>
                      )}
                      {currentMailboxGroup && isLocallyOwnedMailboxGroup(currentMailboxGroup) && (
                        <button
                          className="btn mini primary"
                          onClick={() => focusInviteHub("group", currentMailboxGroup.group_id)}
                        >
                          Invite Hub
                        </button>
                      )}
                      <button
                        className={`btn mini group-members-toggle ${groupMembersPanelOpen ? "active" : ""}`}
                        disabled={!activeConversationGroupId}
                        onClick={() => setGroupMembersPanelOpen((value) => !value)}
                      >
                        {groupMembersPanelOpen ? "Hide Members" : "Members"}
                        {currentMailboxGroup && !currentMailboxGroup.anonymous_group
                          ? ` (${activeGroupMemberIds.length})`
                          : !currentMailboxGroup && observedActiveGroupMembers.length
                            ? ` (${observedActiveGroupMembers.length})`
                            : ""}
                      </button>
                    </div>
                  )}
                </div>

                {activeConversation?.type === "group" && activeConversationGroupId && groupMembersPanelOpen && (
                  <section className="group-members-panel">
                    <div className="group-members-panel-head">
                      <div>
                        <strong>{activeConversationGroupLabel} members</strong>
                        <small className="muted">
                          {currentMailboxGroup
                            ? currentMailboxGroup.anonymous_group
                              ? "Anonymous groups keep member identities hidden."
                              : `${activeGroupMemberIds.length} visible member${activeGroupMemberIds.length === 1 ? "" : "s"}`
                            : observedActiveGroupMembers.length
                              ? `${observedActiveGroupMembers.length} observed member${observedActiveGroupMembers.length === 1 ? "" : "s"} from recent events`
                              : "Syncing mailbox group roster…"}
                        </small>
                        {currentMailboxGroup && !currentMailboxGroup.anonymous_group && (
                          <small className="muted">
                            Handshake starts a 1:1 direct-trust request. Block/Unblock only controls whether that member can request you.
                          </small>
                        )}
                      </div>
                      <div className="group-members-panel-tools">
                        <small className="muted">
                          {currentMailboxGroup
                            ? `${currentMailboxGroup.join_locked ? "Join locked" : "Join open"}${
                                currentMailboxGroup.anonymous_group && mailboxGroupAnonymousSecurityLabel(currentMailboxGroup)
                                  ? ` • ${mailboxGroupAnonymousSecurityLabel(currentMailboxGroup)}`
                                  : ""
                              } • epoch ${currentMailboxGroup.mailbox_epoch}`
                            : `${activeConversationGroupLabel} • ${activeConversationGroupId}`}
                        </small>
                        {currentMailboxGroup && !currentMailboxGroup.anonymous_group && (
                          <button
                            className={`btn mini ${handshakeRequestPolicy.block_all ? "danger" : ""}`}
                            onClick={() =>
                              void safeAction(() =>
                                setHandshakeRequestBlockAll(!handshakeRequestPolicy.block_all)
                              )
                            }
                          >
                            {handshakeRequestPolicy.block_all ? "Allow Requests" : "Block All Requests"}
                          </button>
                        )}
                      </div>
                    </div>

                    {!currentMailboxGroup ? (
                      observedActiveGroupMembers.length ? (
                        <ul className="group-member-list">
                          {observedActiveGroupMembers.map(({ memberId, label }) => (
                            <li key={`${activeConversationGroupId}:${memberId}`} className="group-member-item">
                              <div className="group-member-body">
                                <strong>{label}</strong>
                                <small>{maskDidForUi(visibleDidForRuntimeDid(runtime, memberId), maskDid)}</small>
                              </div>
                              <div className="group-member-actions">
                                <span className="group-member-badge">Observed</span>
                              </div>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="group-members-empty">
                          Mailbox group state is still syncing for {activeConversationGroupLabel}. Try again in a moment.
                        </p>
                      )
                    ) : currentMailboxGroup.anonymous_group ? (
                      <p className="group-members-empty">
                        Ghost/anonymous mailbox groups do not expose a member roster. You can still manage the room from group actions without leaking participant identity.
                      </p>
                    ) : (
                      <ul className="group-member-list">
                        {activeGroupMemberIds.map((memberId) => {
                          const isLocalMember = memberId === currentMailboxGroup.local_member_id;
                          const isOwnerMember = memberId === currentMailboxGroup.owner_member_id;
                          const removable = canKickMailboxGroupMember(currentMailboxGroup, memberId);
                          const memberBlocked = blockedHandshakeMemberIds.has(memberId);
                          const memberTitle = isLocalMember
                            ? "You"
                            : memberDisplayLabel(
                                runtime,
                                memberId,
                                activeGroupMemberDisplayNames.get(memberId) || null
                              );
                          const handshakeCooldownMs = remainingGroupHandshakeInviteCooldownMs(
                            activeAgentName,
                            memberId
                          );
                          return (
                            <li key={`${currentMailboxGroup.group_id}:${memberId}`} className="group-member-item">
                              <div className="group-member-body">
                                <strong>{memberTitle}</strong>
                                <small>{maskDidForUi(visibleDidForRuntimeDid(runtime, memberId), maskDid)}</small>
                              </div>
                              <div className="group-member-actions">
                                {isLocalMember && <span className="group-member-badge">You</span>}
                                {isOwnerMember && <span className="group-member-badge owner">Owner</span>}
                                {!isLocalMember && (
                                  <>
                                    <button
                                      className="btn mini"
                                      disabled={handshakeCooldownMs > 0}
                                      onClick={() =>
                                        void safeAction(() =>
                                          sendGroupHandshakeInvite(currentMailboxGroup.group_id, memberId)
                                        )
                                      }
                                    >
                                      {handshakeCooldownMs > 0
                                        ? `Retry ${Math.ceil(handshakeCooldownMs / 1000)}s`
                                        : "Handshake"}
                                    </button>
                                    <button
                                      className={`btn mini ${memberBlocked ? "" : "danger"}`}
                                      onClick={() =>
                                        void safeAction(() =>
                                          setHandshakeRequestBlock(memberId, !memberBlocked)
                                        )
                                      }
                                    >
                                      {memberBlocked ? "Unblock" : "Block"}
                                    </button>
                                  </>
                                )}
                                {memberBlocked && <span className="group-member-badge">Blocked</span>}
                                {handshakeCooldownMs > 0 && (
                                  <span className="group-member-badge">
                                    Cooldown
                                  </span>
                                )}
                                {removable && (
                                  <button
                                    className="btn mini danger"
                                    onClick={() =>
                                      setPendingGroupKick({
                                        groupId: currentMailboxGroup.group_id,
                                        groupLabel: mailboxGroupLabel(currentMailboxGroup),
                                        memberId,
                                        memberLabel: memberTitle
                                      })
                                    }
                                  >
                                    Remove
                                  </button>
                                )}
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </section>
                )}

                {activeConversation?.type === "dm" && activeConversation.did && !activeAiConversationAgent && (
                  <div className="transfer-policy">
                    <span className="muted">
                      Transfer policy for {cleanPeerName(activeConversation.title, activeConversation.did || undefined)}: {inferTransferPolicy(runtime, activeConversation.did) === "always" ? "ALWAYS_ACCEPT" : "ASK_EVERY_TIME"}
                    </span>
                    <div className="inline">
                      <button className="btn mini" onClick={() => void safeAction(() => applyTransferDecision("ask", activeConversation.did as string))}>
                        Ask Every Time
                      </button>
                      <button className="btn mini" onClick={() => void safeAction(() => applyTransferDecision("always", activeConversation.did as string))}>
                        Always Accept
                      </button>
                    </div>
                  </div>
                )}

                <div
                  ref={chatThreadRef}
                  className="chat-thread"
                  onScroll={(e) => {
                    const el = e.currentTarget;
                    const delta = el.scrollHeight - el.scrollTop - el.clientHeight;
                    stickToBottomRef.current = delta <= 56;
                  }}
                >
                  {!(activeConversation?.messages.length || 0) && (
                    <p className="chat-empty">(no messages yet)</p>
                  )}

                  {(activeConversation?.messages || []).map((m, idx) => {
                    if (m.isTransfer) {
                      if (m.handoffState === "staged" && m.handoffId) {
                        const busy = handoffActionId === m.handoffId;
                        const activeDid = activeConversation?.did || "";
                        return (
                          <div key={`${idx}-handoff`} className="msg-row system">
                            <div className="msg-system-card incoming">
                              <div className="pending-meta">
                                <strong>Secure handoff</strong>
                                <span>{m.handoffFileName || m.text}</span>
                                <small>{maskDidForUi(visibleDidForRuntimeDid(runtime, activeDid), maskDid)}</small>
                              </div>
                              <div className="msg-system-actions">
                                <button
                                  className="btn mini accept"
                                  disabled={busy}
                                  onClick={() => void safeAction(() => exportGhostHandoff(m.handoffId as string))}
                                >
                                  {busy ? "Working..." : "Export"}
                                </button>
                                <button
                                  className="btn mini danger"
                                  disabled={busy}
                                  onClick={() => void safeAction(() => discardGhostHandoff(m.handoffId as string))}
                                >
                                  Discard
                                </button>
                              </div>
                              <div className="msg-system-actions secondary">
                                <button className="btn mini muted-btn" disabled>
                                  Ghost temp only
                                </button>
                                <button className="btn mini muted-btn" disabled>
                                  Receive dir on export
                                </button>
                              </div>
                            </div>
                          </div>
                        );
                      }

                      if (
                        m.transferStage === "incoming_pending" &&
                        m.transferKey &&
                        activeConversation?.type === "dm" &&
                        activeConversation.did
                      ) {
                        const pendingOffer = pendingIncomingTransferOfferByKey.get(m.transferKey) || null;
                        if (pendingOffer) {
                          const busy = transferApprovalActionKey === pendingOffer.transfer_key;
                          return (
                            <div key={`${idx}-pending-transfer`} className="msg-row system">
                              <div className="msg-system-card incoming">
                                <div className="pending-meta">
                                  <strong>Incoming transfer</strong>
                                  <span>{pendingOffer.peer_label}</span>
                                  <small>{maskDidForUi(visibleDidForRuntimeDid(runtime, pendingOffer.did), maskDid)}</small>
                                  <small>{transferEventFileLabel(pendingOffer.filename) || "file"}</small>
                                </div>
                                <div className="msg-system-actions">
                                  <button
                                    className="btn mini accept"
                                    disabled={busy}
                                    onClick={() => void safeAction(() => applyTransferDecision("accept", pendingOffer.did, pendingOffer.transfer_key))}
                                  >
                                    {busy ? "Working..." : "Accept"}
                                  </button>
                                  <button
                                    className="btn mini danger"
                                    disabled={busy}
                                    onClick={() => void safeAction(() => applyTransferDecision("reject", pendingOffer.did, pendingOffer.transfer_key))}
                                  >
                                    Reject
                                  </button>
                                </div>
                                <div className="msg-system-actions secondary">
                                  <button
                                    className="btn mini muted-btn"
                                    disabled={busy}
                                    onClick={() => void safeAction(() => applyTransferDecision("always", pendingOffer.did, pendingOffer.transfer_key))}
                                  >
                                    Always accept
                                  </button>
                                  <button
                                    className="btn mini muted-btn"
                                    disabled={busy}
                                    onClick={() => void safeAction(() => applyTransferDecision("ask", pendingOffer.did, pendingOffer.transfer_key))}
                                  >
                                    Ask every time
                                  </button>
                                </div>
                              </div>
                            </div>
                          );
                        }
                      }

                      if (m.transferStage === "group_offer_pending" && m.transferKey) {
                        const offer = pendingGroupOfferByManifestId.get(m.transferKey) || null;
                        if (offer) {
                          const busy = groupOfferActionId === offer.manifest_id;
                          const senderLabel = offer.anonymous_group
                            ? "anonymous member"
                            : offer.member_display_name || maskDidForUi(offer.sender_member_id || "", maskDid) || "unknown member";
                          return (
                            <div key={`${idx}-pending-group-offer`} className="msg-row system">
                              <div className="msg-system-card incoming">
                                <div className="pending-meta">
                                  <strong>Incoming group file</strong>
                                  <span>{offer.filename || "shared file"}</span>
                                  <small>{senderLabel}</small>
                                  <small>{formatByteCount(offer.size_bytes)}</small>
                                </div>
                                <div className="msg-system-actions">
                                  <button
                                    className="btn mini accept"
                                    disabled={busy}
                                    onClick={() => void safeAction(() => applyGroupFileOfferDecision("accept", offer.manifest_id))}
                                  >
                                    {busy ? "Working..." : "Accept"}
                                  </button>
                                  <button
                                    className="btn mini danger"
                                    disabled={busy}
                                    onClick={() => void safeAction(() => applyGroupFileOfferDecision("reject", offer.manifest_id))}
                                  >
                                    Reject
                                  </button>
                                </div>
                                <div className="msg-system-actions secondary">
                                  <button className="btn mini muted-btn" disabled>
                                    Only accepting members download
                                  </button>
                                  <button className="btn mini muted-btn" disabled>
                                    Manifest {offer.manifest_id.slice(0, 16)}
                                  </button>
                                </div>
                              </div>
                            </div>
                          );
                        }
                      }

                      const isFileMsg = m.text.startsWith("File:") || m.text.startsWith("File sent");
                      const isReceived = m.text.startsWith("File received");
                      const isSent = m.text.startsWith("File sent");
                      const isStaged = m.text.startsWith("Secure handoff ready");
                      const isExported = m.text.startsWith("Secure handoff exported");
                      const isDiscarded = m.text.startsWith("Secure handoff discarded");
                      const isAccepted = m.text.includes("Transfer accepted") || m.text.includes("accepted by");
                      const isRejected = m.text.includes("Transfer rejected") || m.text.includes("rejected by");
                      const isFailed = m.text.includes("transfer failed");
                      const isProgress =
                        m.text.includes("Sending file...") ||
                        m.text.includes("Receiving file...") ||
                        m.text.startsWith("Sending •") ||
                        m.text.startsWith("Receiving •");
                      const isWaiting = m.text.includes("Waiting for") || m.text.includes("Transfer request sent");
                      const isStarted = m.text.includes("transfer started") || m.text.includes("Transfer started");
                      const isIncomingReq = m.text.startsWith("Incoming transfer request");
                      const isDelivered = m.text.startsWith("Delivered");

                      let icon = "";
                      let statusClass = "";
                      if (isDelivered) { icon = "✓✓"; statusClass = "transfer-delivered"; }
                      else if (isExported) { icon = "\u2193"; statusClass = "transfer-success"; }
                      else if (isDiscarded) { icon = "\u2715"; statusClass = "transfer-failed"; }
                      else if (isStaged) { icon = "\u{1F512}"; statusClass = "transfer-waiting"; }
                      else if (isReceived) { icon = "\u2705"; statusClass = "transfer-success"; }
                      else if (isSent) { icon = "\u2705"; statusClass = "transfer-success"; }
                      else if (isAccepted) { icon = "\u2714\uFE0F"; statusClass = "transfer-accepted"; }
                      else if (isRejected || isFailed) { icon = "\u274C"; statusClass = "transfer-failed"; }
                      else if (isProgress) { icon = "\u{1F4E4}"; statusClass = "transfer-progress"; }
                      else if (isWaiting) { icon = "\u23F3"; statusClass = "transfer-waiting"; }
                      else if (isStarted) { icon = "\u{1F680}"; statusClass = "transfer-started"; }
                      else if (isIncomingReq) { icon = "\u{1F4E5}"; statusClass = "transfer-incoming"; }
                      else if (isFileMsg) { icon = "\u{1F4CE}"; statusClass = "transfer-file"; }
                      else { icon = "\u{1F4C1}"; statusClass = "transfer-info"; }

                      // Extract progress percentage for visual bar
                      const progressPercent = isProgress ? Number(m.text.match(/(\d+)%/)?.[1] || "0") : 0;

                      return (
                        <div key={`${idx}-transfer`} className={`msg-row ${m.direction === "out" ? "out" : "in"}`}>
                          <div className={`msg-transfer-bubble ${m.direction === "out" ? "out" : "in"} ${statusClass}`}>
                            <div className="transfer-icon">{icon}</div>
                            <div className="transfer-body">
                              <span className="transfer-text">{m.text}</span>
                              {isProgress && (
                                <div className="transfer-progress-bar">
                                  <div className="transfer-progress-fill" style={{ width: `${progressPercent}%` }} />
                                </div>
                              )}
                              <span className="transfer-label">{m.direction === "out" ? "you" : cleanPeerName(m.sender, undefined)}</span>
                            </div>
                          </div>
                        </div>
                      );
                    }
                    return (
                      <div key={`${idx}-${m.direction}`} className={`msg-row ${m.direction === "out" ? "out" : "in"}`}>
                        <div className={`msg-bubble ${m.direction === "out" ? "out" : "in"}`}>
                          <strong>{m.direction === "out" ? "you" : cleanPeerName(m.sender, undefined)}</strong>
                          <span>{m.text}</span>
                        </div>
                      </div>
                    );
                  })}

                  {(() => {
                    const feedItems = parseTransferFeed(runtime);
                    if (!feedItems.length) return null;
                    return feedItems.map((item, idx) => (
                      <div key={`feed-${idx}`} className="msg-row system">
                        <div className={`msg-transfer-live ${item.kind}`}>
                          <div className="transfer-live-dot" />
                          <span>{item.text}</span>
                        </div>
                      </div>
                    ));
                  })()}
                </div>

                <div className="chat-composer-wrap">
                  {composerMenuOpen && (
                    <div className="composer-menu">
                      {IS_MACOS ? (
                        <button
                          className="composer-menu-item"
                          title="Open file or folder picker"
                          onClick={() => void safeAction(openTransferPicker)}
                        >
                          File / Folder / Anything
                        </button>
                      ) : (
                        <>
                          <button
                            className="composer-menu-item"
                            title="Choose a file to attach"
                            onClick={() => void safeAction(openTransferFilePicker)}
                          >
                            Choose File
                          </button>
                          <button
                            className="composer-menu-item"
                            title="Choose a folder to attach"
                            onClick={() => void safeAction(openTransferFolderPicker)}
                          >
                            Choose Folder
                          </button>
                        </>
                      )}
                    </div>
                  )}

                  <div className="chat-composer">
                    <button
                      className={`composer-plus ${composerMenuOpen ? "open" : ""}`}
                      disabled={!!activeAiConversationAgent}
                      onClick={() => setComposerMenuOpen((v) => !v)}
                      title="File / Folder / Anything"
                      aria-label="File / Folder / Anything"
                    >
                      +
                    </button>
                    <div className="composer-input-stack">
                      {!!pendingFilePath && (
                        <div className="composer-file-chip" title={pendingFilePath}>
                          <span>{pendingTransferLabel(pendingTransferKind, pendingFilePath)} · {pendingFilePath}</span>
                          <button
                            className="composer-file-clear"
                            onClick={() => {
                              setPendingFilePath("");
                              setPendingTransferKind("file");
                            }}
                            aria-label={`Clear selected ${pendingTransferKind}`}
                          >
                            ×
                          </button>
                        </div>
                      )}
                      <input
                        value={messageInput}
                        onChange={(e) => setMessageInput(e.target.value)}
                        placeholder={
                          activeConversation?.type === "group" && !activeConversationGroupId
                            ? "Select a mailbox group first"
                            : activeConversation?.type === "group" && !currentMailboxGroup
                              ? "Syncing mailbox group..."
                            : activeAiConversationAgent
                              ? `Tell ${activeAiConversationAgent} what to do`
                            : pendingFilePath
                              ? `Press Enter to send selected ${pendingTransferKind}`
                              : "Type a secure message"
                        }
                        autoComplete="off"
                        autoCorrect="off"
                        autoCapitalize="off"
                        spellCheck={false}
                        onKeyDown={(e) => {
                          const isComposing = "isComposing" in e.nativeEvent && !!(e.nativeEvent as KeyboardEvent).isComposing;
                          if (isComposing || e.key !== "Enter") return;
                          e.preventDefault();
                          void safeAction(sendMessage);
                        }}
                      />
                    </div>
                    <button
                      className="btn primary composer-send"
                      disabled={
                        (activeConversation?.type === "group" && !activeConversationGroupId) ||
                        (!!pendingFilePath && transferSubmitLock) ||
                        (!!activeAiConversationAgent && !!pendingFilePath)
                      }
                      onClick={() => void safeAction(sendMessage)}
                    >
                      {pendingFilePath
                        ? `Send ${pendingTransferKind === "folder" ? "Folder" : "File"}`
                        : activeAiConversationAgent
                          ? "Send to Agent"
                          : "Send"}
                    </button>
                  </div>
                </div>

                <div className="connect-panel">
                  {!!runtime?.contact_did && (
                    <>
                      <label className="connect-panel-label" htmlFor="local-contact-did">Your contact DID</label>
                      <div className="connect-panel-row">
                        <textarea
                          id="local-contact-did"
                          rows={3}
                          value={runtime.contact_did}
                          readOnly
                        />
                        <button
                          className="btn mini"
                          onClick={() => void safeAction(() => copyTextWithPolicy(runtime.contact_did || "", "Contact DID"))}
                        >
                          Copy
                        </button>
                      </div>
                    </>
                  )}
                  <label className="connect-panel-label" htmlFor="invite-connect-input">Connect invite code</label>
                  <div className="connect-panel-row">
                    <textarea
                      id="invite-connect-input"
                      rows={2}
                      value={inviteCodeInput}
                      onChange={(e) => setInviteCodeInput(e.target.value)}
                      placeholder="Paste invite code"
                    />
                    <button className="btn mini" onClick={() => void safeAction(connectByInvite)}>Connect</button>
                  </div>
                  <label className="connect-panel-label" htmlFor="did-connect-input">Connect by contact DID</label>
                  <div className="connect-panel-row">
                    <textarea
                      id="did-connect-input"
                      rows={2}
                      value={didConnectInput}
                      onChange={(e) => setDidConnectInput(e.target.value)}
                      placeholder="Paste did:qypha:..."
                    />
                    <button className="btn mini" onClick={() => void safeAction(connectByDid)}>Connect</button>
                  </div>
                  <small className="muted invite-security-note">
                    DID-first connect is preferred. Share the exported contact DID and connect with
                    <code> did:qypha:...</code> without exposing IP metadata in the invite code.
                  </small>
                </div>
              </section>
            </div>
          </article>

          {inviteHubCard}
          {aiSkillsCard}

          <article className="card big">
            <h2>Runtime Logs</h2>
            <pre className="logbox">
              {isGhost
                ? "Ghost mode: runtime logs hidden in UI (memory-only session)."
                : displayedRuntimeLogs.join("\n")}
            </pre>
          </article>
        </section>
      </main>

      {!!pendingDelete && (
        <div className="modal-backdrop" onClick={() => setPendingDelete(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h3>
              {pendingDelete.mode === "full"
                ? "Delete & Disconnect?"
                : pendingDelete.mode === "group_chat"
                  ? "Delete Group Chat?"
                : pendingDelete.mode === "disconnect"
                  ? "Disconnect Peer?"
                  : pendingDelete.mode === "group_disband"
                    ? "Delete & Disband Group?"
                    : pendingDelete.mode === "group_leave"
                      ? "Leave & Delete Group?"
                  : "Delete Chat?"}
            </h3>
            <p className="muted">
              {pendingDelete.mode === "full"
                ? `${pendingDelete.label} — chat history will be deleted and the peer connection will be dropped.${runtime?.mode === "safe" ? " In Safe mode this also forgets the peer until a new invite is used." : ""}`
                : pendingDelete.mode === "group_chat"
                  ? `${pendingDelete.label} — this local group chat history will be removed from Conversations, but you will stay joined to the mailbox group.`
                : pendingDelete.mode === "disconnect"
                  ? `${pendingDelete.label} — the live peer connection will be closed and any saved auto-reconnect pairing will be removed. Existing chat history stays visible.`
                  : pendingDelete.mode === "group_disband"
                    ? `${pendingDelete.label} — this mailbox group will be deleted locally and disbanded for every member, then removed from Conversations and Group Management.`
                    : pendingDelete.mode === "group_leave"
                      ? `${pendingDelete.label} — you will leave this mailbox group and its conversation will be removed from Conversations.`
                  : `${pendingDelete.label} — chat history will be deleted but the connection stays active.`}
            </p>
            <div className="modal-actions">
              <button className="btn" onClick={() => setPendingDelete(null)}>Cancel</button>
              <button
                className="btn danger"
                onClick={() => {
                  const target = pendingDelete;
                  if (!target) return;
                  setPendingDelete(null);
                  if (target.mode === "chat" || target.mode === "group_chat" || target.mode === "full") {
                    deleteConversation(target.agentName, target.key);
                  }
                  if (target.did) {
                    void ensureBackendActiveAgent(target.agentName)
                      .then(async () => {
                        if (target.mode === "chat" || target.mode === "full") {
                          await invokeOrThrow<void>("runtime_forget_peer_history", { did: target.did });
                        }
                        if (target.mode === "full" || target.mode === "disconnect") {
                          await invokeOrThrow<void>("runtime_disconnect_peer", { did: target.did });
                        }
                      })
                      .then(() => refreshSnapshot(true))
                      .catch((err) => setUiFeedback(String(err), true));
                  }
                  if ((target.mode === "group_leave" || target.mode === "group_disband") && target.groupId) {
                    void removeMailboxGroupConversation(
                      target.agentName,
                      target.groupId,
                      target.mode === "group_disband" ? "disband" : "leave",
                      target.label
                    ).catch((err) => setUiFeedback(String(err), true));
                  }
                }}
              >
                {pendingDelete.mode === "full"
                  ? "Delete & Disconnect"
                  : pendingDelete.mode === "group_chat"
                    ? "Delete Chat"
                  : pendingDelete.mode === "disconnect"
                    ? "Disconnect"
                    : pendingDelete.mode === "group_disband"
                      ? "Delete & Disband Group"
                      : pendingDelete.mode === "group_leave"
                        ? "Leave & Delete Group"
                    : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}

      {!!pendingAgentDestroy && (
        <div className="modal-backdrop" onClick={() => setPendingAgentDestroy(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h3>{pendingAgentDestroy.mode === "all" ? "Delete all agents?" : "Delete agent?"}</h3>
            <p className="muted">
              {pendingAgentDestroy.mode === "all"
                ? "All saved agents, encrypted identities, Tor state, logs and config files will be permanently deleted."
                : `${pendingAgentDestroy.agentName} will be permanently deleted together with its encrypted identity, Tor state, logs and config file.`}
            </p>
            <div className="modal-actions">
              <button className="btn" onClick={() => setPendingAgentDestroy(null)}>Cancel</button>
              <button
                className="btn danger"
                onClick={() =>
                  void safeAction(() =>
                    pendingAgentDestroy.mode === "all"
                      ? destroyAllAgents()
                      : destroyAgent(pendingAgentDestroy.agentName || "")
                  )
                }
              >
                {pendingAgentDestroy.mode === "all" ? "Delete all" : "Delete agent"}
              </button>
            </div>
          </div>
        </div>
      )}

      {!!pendingGroupKick && (
        <div className="modal-backdrop" onClick={() => setPendingGroupKick(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h3>Remove Member?</h3>
            <p className="muted">
              {pendingGroupKick.memberLabel} will be removed from {pendingGroupKick.groupLabel}. They will lose mailbox access and need a fresh invite to rejoin.
            </p>
            <div className="modal-actions">
              <button className="btn" onClick={() => setPendingGroupKick(null)}>Cancel</button>
              <button
                className="btn danger"
                onClick={() => {
                  const target = pendingGroupKick;
                  if (!target) return;
                  setPendingGroupKick(null);
                  void safeAction(() => kickMailboxGroupMember(target.memberId));
                }}
              >
                Remove Member
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export interface LegacyGroupSeed {
  groupId: string;
  groupLabel: string;
}

export interface LegacyGroupTimelineEntry {
  groupId: string;
  groupLabel: string;
  sender: string;
  text: string;
  sortMs: number;
}

interface GroupLike {
  group_id: string;
  group_name?: string | null;
}

interface ExistingGroupLike {
  groupId: string;
  groupLabel: string;
}

interface CollectLegacyGroupLogFallbackOptions {
  logs: string[];
  knownGroups?: GroupLike[];
  existingGroups?: ExistingGroupLike[];
  structuredGroupIds?: Iterable<string>;
  initialSyntheticTs?: number;
}

const GROUP_ID_PATTERN = /^(grp_|gmbx_|group:)[A-Za-z0-9:_-]+$/;
const DID_PATTERN = /did:(?:nxf:[0-9a-fA-F]{32,128}|qypha:[1-9A-HJ-NP-Za-km-z]{32,128})/;

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

function extractLeadingTimestampMs(line: string): number | null {
  const match = String(line || "").match(/^(\d{4}-\d{2}-\d{2}T\S+?)\s/);
  if (!match) return null;
  const parsed = Date.parse(match[1]);
  return Number.isFinite(parsed) ? parsed : null;
}

function looksLikeGroupId(value: string | null | undefined): boolean {
  return GROUP_ID_PATTERN.test(String(value || "").trim());
}

function normalizeLabel(label: string): string {
  return label.trim().toLowerCase();
}

function parseGroupJoinLine(line: string): LegacyGroupSeed | null {
  const match = line.match(/^Group invite joined:\s+(.+?)\s+\(((?:grp_|gmbx_|group:)[A-Za-z0-9:_-]+)\)$/);
  if (!match) return null;
  const groupLabel = match[1].trim();
  const groupId = match[2].trim();
  if (!groupLabel || !looksLikeGroupId(groupId)) return null;
  return { groupId, groupLabel };
}

function parseGroupOutgoingCommand(line: string): { groupId: string; message: string } | null {
  const normalized = stripAnsi(line).trim();
  let body = "";

  if (normalized.startsWith("> ")) {
    body = normalized.slice(2).trim();
  } else {
    const markerIdx = normalized.indexOf(" > ");
    if (markerIdx < 0) return null;
    const prefix = normalized.slice(0, markerIdx).trim();
    if (!/^[A-Za-z0-9_-]+(?:\[[^\]]+\])?$/.test(prefix)) return null;
    body = normalized.slice(markerIdx + 3).trim();
  }

  if (!body.startsWith("/sendto ")) return null;
  const payload = body.slice("/sendto ".length);
  const firstSpace = payload.indexOf(" ");
  if (firstSpace < 1) return null;
  const target = payload.slice(0, firstSpace).trim();
  const message = payload.slice(firstSpace + 1).trim();
  if (!looksLikeGroupId(target) || !message) return null;
  return { groupId: target, message };
}

function parseMembershipLine(line: string): { groupLabel: string; text: string } | null {
  const joined = line.match(new RegExp(`^\\[(.+?)\\]\\s+(.+?)\\s+joined as\\s+(${DID_PATTERN.source})$`));
  if (joined) {
    return {
      groupLabel: joined[1].trim(),
      text: `member joined • ${joined[2].trim()}`
    };
  }
  const left = line.match(new RegExp(`^\\[(.+?)\\]\\s+(.+?)\\s+left\\s+\\((${DID_PATTERN.source})\\)$`));
  if (left) {
    return {
      groupLabel: left[1].trim(),
      text: `member left • ${left[2].trim()}`
    };
  }
  return null;
}

function parseSystemLine(line: string): { groupLabel: string; text: string } | null {
  const directTrust = line.match(new RegExp(`^\\[(.+?)\\]\\s+(${DID_PATTERN.source})\\s+requested direct trust\\.`));
  if (directTrust) {
    return {
      groupLabel: directTrust[1].trim(),
      text: `direct trust offer from ${directTrust[2]}`
    };
  }
  const disbanded = line.match(new RegExp(`^\\[(.+?)\\]\\s+disbanded by owner\\s+\\((${DID_PATTERN.source})\\)$`));
  if (disbanded) {
    return {
      groupLabel: disbanded[1].trim(),
      text: `group disbanded • owner ${disbanded[2]}`
    };
  }
  const mailboxState = line.match(/^\[(.+?)\]\s+mailbox\s+(locked|unlocked)\s+at epoch\s+(\d+)$/);
  if (mailboxState) {
    return {
      groupLabel: mailboxState[1].trim(),
      text: `mailbox ${mailboxState[2]} • epoch ${mailboxState[3]}`
    };
  }
  const rotation = line.match(new RegExp(`^\\[(.+?)\\]\\s+rotated mailbox epoch\\s+(\\d+)\\s+and removed\\s+(${DID_PATTERN.source})$`));
  if (rotation) {
    return {
      groupLabel: rotation[1].trim(),
      text: `mailbox epoch ${rotation[2]} • removed ${rotation[3]}`
    };
  }
  return null;
}

function parseChatLine(line: string): { groupLabel: string; sender: string; text: string } | null {
  const bracket = line.match(/^\[(.+?)\]\s+(.+)$/);
  if (!bracket) return null;
  const groupLabel = bracket[1].trim();
  const rest = bracket[2].trim();
  if (!groupLabel || !rest) return null;
  if (
    rest.includes(" joined as ") ||
    rest.includes(" left (") ||
    rest.includes(" requested direct trust.") ||
    rest.includes(" disbanded by owner") ||
    rest.startsWith("mailbox ") ||
    rest.startsWith("rotated mailbox epoch ")
  ) {
    return null;
  }
  const senderMatch = rest.match(
    new RegExp(`^(.+?\\s+\\(${DID_PATTERN.source}\\)|${DID_PATTERN.source}|anonymous member|you)\\s+(.+)$`)
  );
  if (!senderMatch) return null;
  const sender = senderMatch[1].trim();
  const text = senderMatch[2].trim();
  if (!sender || !text) return null;
  return { groupLabel, sender, text };
}

export function collectLegacyGroupLogFallback(
  options: CollectLegacyGroupLogFallbackOptions
): { seeds: LegacyGroupSeed[]; entries: LegacyGroupTimelineEntry[] } {
  const logs = options.logs || [];
  const structuredGroupIds = new Set(
    [...(options.structuredGroupIds || [])].map((value) => String(value || "").trim()).filter(Boolean)
  );
  const labelToGroupId = new Map<string, string>();
  const groupLabelById = new Map<string, string>();
  const outgoingIndexesBySignature = new Map<string, number[]>();

  const rememberGroup = (groupId: string, groupLabel: string): void => {
    if (!looksLikeGroupId(groupId)) return;
    const label = groupLabel.trim() || groupId;
    const currentLabel = groupLabelById.get(groupId);
    if (!currentLabel || currentLabel === groupId) {
      groupLabelById.set(groupId, label);
    }
    labelToGroupId.set(normalizeLabel(label), groupId);
  };

  for (const group of options.existingGroups || []) {
    rememberGroup(group.groupId, group.groupLabel);
  }
  for (const group of options.knownGroups || []) {
    rememberGroup(group.group_id, group.group_name?.trim() || group.group_id);
  }

  logs.forEach((raw, index) => {
    const clean = stripRuntimePrefix(stripAnsi(raw).trim());
    if (!clean) return;
    const join = parseGroupJoinLine(clean);
    if (join) {
      rememberGroup(join.groupId, join.groupLabel);
    }
    const outgoing = parseGroupOutgoingCommand(raw);
    if (!outgoing) return;
    const signature = `${outgoing.groupId}\u0000${outgoing.message}`;
    const bucket = outgoingIndexesBySignature.get(signature) || [];
    bucket.push(index);
    outgoingIndexesBySignature.set(signature, bucket);
    rememberGroup(outgoing.groupId, groupLabelById.get(outgoing.groupId) || outgoing.groupId);
  });

  const seeds = [...groupLabelById.entries()].map(([groupId, groupLabel]) => ({ groupId, groupLabel }));
  const entries: LegacyGroupTimelineEntry[] = [];
  let syntheticTs = options.initialSyntheticTs ?? Date.now() - logs.length;

  logs.forEach((raw, index) => {
    const clean = stripRuntimePrefix(stripAnsi(raw).trim());
    if (!clean) return;

    const join = parseGroupJoinLine(clean);
    if (join && !structuredGroupIds.has(join.groupId)) {
      const sortMs = extractLeadingTimestampMs(raw) ?? (syntheticTs += 1);
      entries.push({
        groupId: join.groupId,
        groupLabel: groupLabelById.get(join.groupId) || join.groupLabel,
        sender: "system",
        text: "joined mailbox group",
        sortMs
      });
      return;
    }

    const membership = parseMembershipLine(clean);
    if (membership) {
      const groupId = labelToGroupId.get(normalizeLabel(membership.groupLabel));
      if (!groupId || structuredGroupIds.has(groupId)) return;
      const sortMs = extractLeadingTimestampMs(raw) ?? (syntheticTs += 1);
      entries.push({
        groupId,
        groupLabel: groupLabelById.get(groupId) || membership.groupLabel,
        sender: "system",
        text: membership.text,
        sortMs
      });
      return;
    }

    const system = parseSystemLine(clean);
    if (system) {
      const groupId = labelToGroupId.get(normalizeLabel(system.groupLabel));
      if (!groupId || structuredGroupIds.has(groupId)) return;
      const sortMs = extractLeadingTimestampMs(raw) ?? (syntheticTs += 1);
      entries.push({
        groupId,
        groupLabel: groupLabelById.get(groupId) || system.groupLabel,
        sender: "system",
        text: system.text,
        sortMs
      });
      return;
    }

    const chat = parseChatLine(clean);
    if (!chat) return;
    const groupId = labelToGroupId.get(normalizeLabel(chat.groupLabel));
    if (!groupId || structuredGroupIds.has(groupId)) return;

    const signature = `${groupId}\u0000${chat.text}`;
    const bucket = outgoingIndexesBySignature.get(signature);
    const pendingEchoIndex = bucket?.[0];
    if (typeof pendingEchoIndex === "number" && pendingEchoIndex <= index && index - pendingEchoIndex <= 6) {
      bucket?.shift();
      return;
    }

    const sortMs = extractLeadingTimestampMs(raw) ?? (syntheticTs += 1);
    entries.push({
      groupId,
      groupLabel: groupLabelById.get(groupId) || chat.groupLabel,
      sender: chat.sender,
      text: chat.text,
      sortMs
    });
  });

  return { seeds, entries };
}

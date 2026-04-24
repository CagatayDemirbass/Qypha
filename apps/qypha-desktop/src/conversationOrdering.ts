export interface ConversationOrderMessageLike {
  seq?: number;
  tsMs?: number | null;
}

export interface ConversationOrderItemLike {
  key: string;
  type: "group" | "dm";
  title: string;
  messages: ConversationOrderMessageLike[];
}

export function conversationActivityTimestamp(
  conversation: ConversationOrderItemLike
): number {
  const lastMessage = conversation.messages[conversation.messages.length - 1];
  if (!lastMessage) return 0;
  if (typeof lastMessage.tsMs === "number" && Number.isFinite(lastMessage.tsMs)) {
    return lastMessage.tsMs;
  }
  return 0;
}

export function sortConversationsByActivity<T extends ConversationOrderItemLike>(
  conversations: T[]
): T[] {
  return [...conversations].sort((a, b) => {
    const aTs = conversationActivityTimestamp(a);
    const bTs = conversationActivityTimestamp(b);
    if (aTs !== bTs) return bTs - aTs;

    const aSeq = a.messages[a.messages.length - 1]?.seq || 0;
    const bSeq = b.messages[b.messages.length - 1]?.seq || 0;
    if (aSeq !== bSeq) return bSeq - aSeq;

    return a.title.localeCompare(b.title);
  });
}

export function defaultConversationKey<T extends ConversationOrderItemLike>(
  conversations: T[]
): string {
  return sortConversationsByActivity(conversations)[0]?.key || "";
}

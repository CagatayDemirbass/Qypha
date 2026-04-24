export interface ConversationPresenceLike {
  type: "group" | "dm";
  did: string | null;
  messages: unknown[];
  isExplicit?: boolean;
  isPeerListed?: boolean;
}

export function shouldRenderConversationInList(
  conversation: ConversationPresenceLike
): boolean {
  if (conversation.type !== "dm") return true;
  if (!conversation.did) return conversation.messages.length > 0;
  return (
    conversation.messages.length > 0 ||
    !!conversation.isExplicit ||
    !!conversation.isPeerListed
  );
}

export function shouldKeepImplicitDmConversation(
  conversation: ConversationPresenceLike,
  isActiveConversation: boolean
): boolean {
  if (conversation.type !== "dm") return true;
  if (conversation.messages.length > 0 || conversation.isExplicit || conversation.isPeerListed) {
    return true;
  }
  return isActiveConversation;
}

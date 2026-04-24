export interface MailboxGroupHydrationSnapshot {
  runtime: {
    mailbox_groups?: Array<{
      group_id: string;
    }> | null;
  } | null;
}

export function snapshotContainsMailboxGroup(
  snapshot: MailboxGroupHydrationSnapshot | null | undefined,
  groupId: string | null | undefined
): boolean {
  const targetGroupId = groupId?.trim();
  if (!targetGroupId) return false;
  return !!snapshot?.runtime?.mailbox_groups?.some((group) => group.group_id === targetGroupId);
}

export async function hydrateMissingMailboxGroupSnapshot<T extends MailboxGroupHydrationSnapshot>(
  groupId: string,
  tryLoad: () => Promise<T>,
  forceLoad: () => Promise<T>
): Promise<T> {
  const optimistic = await tryLoad();
  if (snapshotContainsMailboxGroup(optimistic, groupId)) {
    return optimistic;
  }
  return forceLoad();
}

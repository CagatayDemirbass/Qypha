type MailboxGroupLabelSource = {
  group_id?: string | null;
  group_name?: string | null;
};

export function resolveMailboxGroupConversationLabel(
  groupId: string | null | undefined,
  preferredGroupName?: string | null,
  group?: MailboxGroupLabelSource | null
): string {
  const explicitName = preferredGroupName?.trim();
  if (explicitName) return explicitName;

  const snapshotName = group?.group_name?.trim();
  if (snapshotName) return snapshotName;

  const snapshotGroupId = group?.group_id?.trim();
  if (snapshotGroupId) return snapshotGroupId;

  const fallbackGroupId = groupId?.trim();
  if (fallbackGroupId) return fallbackGroupId;

  return "Mailbox Group";
}

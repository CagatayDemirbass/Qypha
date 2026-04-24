use super::*;

impl GroupMailboxRegistry {
    fn normalize_member_selector(selector: &str) -> String {
        let trimmed = selector.trim();
        crate::network::contact_did::decode_contact_did(trimmed)
            .map(|resolved| resolved.canonical_did)
            .unwrap_or_else(|_| trimmed.to_string())
    }

    pub fn persistence_for_log_mode(mode: &str) -> GroupMailboxPersistence {
        if mode.eq_ignore_ascii_case("ghost") {
            GroupMailboxPersistence::MemoryOnly
        } else {
            GroupMailboxPersistence::EncryptedDisk
        }
    }

    pub fn configure_persistence(
        &mut self,
        persist_path: Option<PathBuf>,
        persist_key: Option<[u8; 32]>,
    ) {
        self.persist_path = persist_path;
        self.persist_key = persist_key;
    }

    pub fn load_persisted(&mut self) -> Result<()> {
        let path = match &self.persist_path {
            Some(path) => path.clone(),
            None => return Ok(()),
        };
        let key = match self.persist_key {
            Some(key) => key,
            None => return Ok(()),
        };
        let encoded = match std::fs::read(&path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "Failed to read persisted mailbox groups from {}: {}",
                    path.display(),
                    error
                ))
            }
        };
        let registry = match decode_persisted_group_mailbox_registry(&encoded, &key) {
            Ok(registry) => registry,
            Err(error) => {
                if should_quarantine_persisted_mailbox_group_blob(&error) {
                    delete_corrupted_persisted_mailbox_group_blob(&path);
                    wipe_orphaned_group_chunk_staging_root(&path);
                    self.clear_in_memory_state();
                    return Err(anyhow::anyhow!(
                        "Corrupted persisted mailbox group state at {} was securely deleted; joined mailbox groups and unfinished group transfers were reset",
                        path.display()
                    ));
                }
                return Err(error);
            }
        };

        self.clear_in_memory_state();
        for persisted in registry.sessions {
            let session = persisted.into_session()?;
            self.sessions.insert(session.group_id.clone(), session);
        }
        for persisted in registry.tombstones {
            let tombstone = persisted.into_tombstone()?;
            self.tombstones
                .insert(tombstone.group_id.clone(), tombstone);
        }
        for mut download in registry.chunk_downloads {
            if download.crypto_context.group_id.is_empty() {
                let Some(session) = self.sessions.get(&download.group_id) else {
                    secure_wipe_dir(&download.recv.temp_dir);
                    continue;
                };
                download.crypto_context = GroupMailboxCryptoContext {
                    group_id: session.group_id.clone(),
                    anonymous_group: session.anonymous_group,
                    mailbox_capability: download.mailbox_capability.clone(),
                    content_crypto_state: session.content_crypto_state.clone(),
                    anonymous_writer_state: session.anonymous_writer_state.clone(),
                };
            }
            self.chunk_downloads
                .insert(download.transfer_id.clone(), download);
        }
        for offer in registry.pending_file_offers {
            self.pending_file_offers
                .insert(offer.manifest_id.clone(), offer);
        }
        for offer in registry.pending_handshake_offers {
            self.pending_handshake_offers
                .insert(offer.sender_member_id.clone(), offer);
        }
        Ok(())
    }

    pub fn persist_now(&self) -> Result<()> {
        self.persist_to_disk()
    }

    pub fn join_from_invite(
        &mut self,
        invite: &crate::network::group_invite_bundle::ResolvedGroupMailboxInvite,
        persistence: GroupMailboxPersistence,
        local_member_id: Option<String>,
    ) -> Result<()> {
        if mailbox_namespace_group_label(&invite.mailbox_descriptor.namespace) != invite.group_id {
            bail!(
                "Mailbox invite namespace/group mismatch for {}. Request a fresh invite.",
                invite.group_id
            );
        }
        if self.sessions.contains_key(&invite.group_id) {
            bail!(
                "Mailbox group {} is already joined. Leave it before using another invite.",
                invite.group_id
            );
        }
        if invite.join_locked {
            bail!(
                "Mailbox group {} is locked. Ask the owner to unlock the group and send a fresh invite.",
                invite.group_id
            );
        }
        if let Some(content_crypto_state) = invite.content_crypto_state.as_ref() {
            validate_group_content_crypto_state(content_crypto_state, &invite.group_id)?;
        }
        validate_anonymous_group_state_pair(
            invite.anonymous_group,
            &invite.group_id,
            invite.content_crypto_state.as_ref(),
            invite.anonymous_writer_state.as_ref(),
        )?;
        let invite_epoch = mailbox_namespace_epoch(&invite.mailbox_descriptor.namespace)?;
        if let Some(tombstone) = self.tombstones.get(&invite.group_id) {
            if tombstone.disbanded && invite_epoch <= tombstone.mailbox_epoch {
                bail!(
                    "Mailbox group {} was disbanded at epoch {}. Ask the owner to create a fresh group invite.",
                    invite.group_id,
                    tombstone.mailbox_epoch
                );
            }
            if invite_epoch < tombstone.mailbox_epoch {
                bail!(
                    "Mailbox invite for {} is stale (invite epoch {} < last seen epoch {}). Ask the owner for a fresh invite.",
                    invite.group_id,
                    invite_epoch,
                    tombstone.mailbox_epoch
                );
            }
            if tombstone.join_locked && invite_epoch == tombstone.mailbox_epoch {
                bail!(
                    "Mailbox group {} was locked at epoch {} when you last left it. Ask the owner to unlock the group and send a fresh invite.",
                    invite.group_id,
                    tombstone.mailbox_epoch
                );
            }
        }
        self.insert_session(GroupMailboxSession {
            group_id: invite.group_id.clone(),
            group_name: invite.group_name.clone(),
            anonymous_group: invite.anonymous_group,
            join_locked: invite.join_locked,
            mailbox_descriptor: invite.mailbox_descriptor.clone(),
            mailbox_capability: invite.mailbox_capability.clone(),
            content_crypto_state: invite.content_crypto_state.clone(),
            anonymous_writer_state: invite.anonymous_writer_state.clone(),
            local_member_id,
            owner_member_id: if invite.anonymous_group {
                None
            } else {
                invite.issuer_did.clone()
            },
            persistence,
            joined_at: chrono::Utc::now().timestamp() as u64,
            invite_id: invite.invite_id.clone(),
            owner_special_id: None,
            mailbox_epoch: invite_epoch,
            poll_cursor: invite
                .anonymous_group
                .then(|| MAILBOX_CURSOR_TAIL.to_string()),
            next_cover_traffic_at: invite
                .anonymous_group
                .then(|| next_ghost_anonymous_cover_traffic_at(current_unix_ts_ms())),
            last_real_activity_at: invite.anonymous_group.then(current_unix_ts_ms),
            known_members: HashMap::new(),
            local_posted_message_ids: HashSet::new(),
            seen_message_ids: HashMap::new(),
            join_bridge_handles: Vec::new(),
        })
    }

    pub fn insert_session(&mut self, session: GroupMailboxSession) -> Result<()> {
        validate_group_mailbox_session(&session)?;
        self.tombstones.remove(&session.group_id);
        self.mailbox_manual_refresh_at.remove(&session.group_id);
        self.sessions.insert(session.group_id.clone(), session);
        self.persist_to_disk()
    }

    pub fn get(&self, group_id: &str) -> Option<&GroupMailboxSession> {
        self.sessions.get(group_id)
    }

    pub fn get_cloned(&self, group_id: &str) -> Option<GroupMailboxSession> {
        self.sessions.get(group_id).cloned()
    }

    pub fn get_by_owner_special_id_cloned(
        &self,
        owner_special_id: &str,
    ) -> Option<GroupMailboxSession> {
        self.sessions
            .values()
            .find(|session| session.owner_special_id.as_deref() == Some(owner_special_id))
            .cloned()
    }

    pub fn list_group_ids(&self) -> Vec<String> {
        let mut ids = self.sessions.keys().cloned().collect::<Vec<_>>();
        ids.sort();
        ids
    }

    pub fn cloned_sessions(&self) -> Vec<GroupMailboxSession> {
        let mut sessions = self.sessions.values().cloned().collect::<Vec<_>>();
        sessions.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        sessions
    }

    pub fn summaries(&self) -> Vec<GroupMailboxSummary> {
        let mut items = self
            .sessions
            .values()
            .map(|session| GroupMailboxSummary {
                group_id: session.group_id.clone(),
                group_name: session.group_name.clone(),
                anonymous_group: session.anonymous_group,
                anonymous_security_state: anonymous_group_security_state(session),
                join_locked: session.join_locked,
                persistence: session.persistence.clone(),
                local_member_id: session.local_member_id.clone(),
                owner_member_id: session.owner_member_id.clone(),
                owner_special_id: session.owner_special_id.clone(),
                known_members: known_members_sorted(session),
                known_member_ids: known_member_ids_sorted(session),
                mailbox_epoch: session.mailbox_epoch,
                degraded: self
                    .mailbox_transport_backoff
                    .get(&session.group_id)
                    .is_some_and(|state| mailbox_transport_is_degraded(state.failures)),
            })
            .collect::<Vec<_>>();
        items.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        items
    }

    pub fn clear(&mut self) -> Result<()> {
        self.clear_in_memory_state();
        self.persist_to_disk()
    }

    pub(crate) fn clear_in_memory_state(&mut self) {
        for download in self.chunk_downloads.values() {
            secure_wipe_dir(&download.recv.temp_dir);
        }
        for transfer in self.staged_fast_file_transfers.values() {
            secure_wipe_file(&transfer.packed_path);
        }
        self.sessions.clear();
        self.tombstones.clear();
        self.chunk_downloads.clear();
        self.pending_file_offers.clear();
        self.pending_handshake_offers.clear();
        self.pending_fast_file_offers.clear();
        self.staged_fast_file_transfers.clear();
        self.pending_fast_file_grants.clear();
        self.active_fast_file_sender_refs.clear();
        self.mailbox_transport_backoff.clear();
        self.mailbox_manual_refresh_at.clear();
    }

    pub fn mark_local_post(&mut self, group_id: &str, message_id: &str) {
        if let Some(session) = self.sessions.get_mut(group_id) {
            session
                .local_posted_message_ids
                .insert(message_id.to_string());
            note_group_activity(session, current_unix_ts_ms());
        }
    }

    pub fn consume_local_post_marker(&mut self, group_id: &str, message_id: &str) -> bool {
        self.sessions
            .get_mut(group_id)
            .map(|session| session.local_posted_message_ids.remove(message_id))
            .unwrap_or(false)
    }

    pub fn mark_message_seen(&mut self, group_id: &str, message_id: &str, created_at: u64) -> bool {
        let Some(session) = self.sessions.get_mut(group_id) else {
            return false;
        };
        prune_seen_message_ids(session, current_unix_ts());
        if session.seen_message_ids.contains_key(message_id) {
            return false;
        }
        session
            .seen_message_ids
            .insert(message_id.to_string(), created_at);
        prune_seen_message_ids(session, current_unix_ts());
        true
    }

    pub fn note_real_activity(&mut self, group_id: &str) {
        if let Some(session) = self.sessions.get_mut(group_id) {
            note_group_activity(session, current_unix_ts_ms());
        }
    }

    pub fn anonymous_cover_traffic_due(&self, group_id: &str, now: u64) -> bool {
        self.sessions
            .get(group_id)
            .filter(|session| session.anonymous_group)
            .and_then(|session| session.next_cover_traffic_at)
            .map(|deadline| deadline <= now)
            .unwrap_or(false)
    }

    pub fn reschedule_anonymous_cover_traffic(&mut self, group_id: &str, now: u64) {
        if let Some(session) = self.sessions.get_mut(group_id) {
            if session.anonymous_group {
                session.next_cover_traffic_at = Some(next_ghost_anonymous_cover_traffic_at(now));
            }
        }
    }

    pub fn update_poll_cursor(
        &mut self,
        group_id: &str,
        next_cursor: Option<String>,
    ) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(group_id) {
            if session.poll_cursor == next_cursor {
                return Ok(());
            }
            session.poll_cursor = next_cursor;
            return self.persist_to_disk();
        }
        Ok(())
    }

    pub fn update_mailbox_endpoint(&mut self, group_id: &str, endpoint: &str) -> Result<bool> {
        let Some(session) = self.sessions.get_mut(group_id) else {
            return Ok(false);
        };
        if session.mailbox_descriptor.endpoint.as_deref() == Some(endpoint) {
            return Ok(false);
        }
        session.mailbox_descriptor.endpoint = Some(endpoint.to_string());
        self.mailbox_transport_backoff.remove(group_id);
        self.persist_to_disk()?;
        Ok(true)
    }

    pub fn mailbox_transport_due(&self, group_id: &str, now_ms: u64) -> bool {
        self.mailbox_transport_backoff
            .get(group_id)
            .and_then(|state| state.next_attempt_at_ms)
            .map(|deadline| deadline <= now_ms)
            .unwrap_or(true)
    }

    pub fn note_mailbox_transport_success(&mut self, group_id: &str) -> Option<u32> {
        self.mailbox_transport_backoff
            .remove(group_id)
            .map(|state| state.failures)
    }

    pub fn take_manual_mailbox_refresh_slot(&mut self, group_id: &str, now_ms: u64) -> bool {
        if !self.sessions.contains_key(group_id) {
            return false;
        }
        let allowed = self
            .mailbox_manual_refresh_at
            .get(group_id)
            .map(|last_attempt| {
                now_ms.saturating_sub(*last_attempt) >= MAILBOX_MANUAL_REFRESH_MIN_INTERVAL_MS
            })
            .unwrap_or(true);
        if allowed {
            self.mailbox_manual_refresh_at
                .insert(group_id.to_string(), now_ms);
        }
        allowed
    }

    pub fn note_mailbox_transport_failure(
        &mut self,
        group_id: &str,
        poll_interval_ms: u64,
        now_ms: u64,
    ) -> MailboxTransportFailureOutcome {
        let state = self
            .mailbox_transport_backoff
            .entry(group_id.to_string())
            .or_default();
        state.failures = state.failures.saturating_add(1);
        let base = poll_interval_ms.max(MAILBOX_TRANSPORT_MIN_RETRY_MS);
        let shift = state.failures.saturating_sub(1).min(4);
        let retry_after_ms =
            (base.saturating_mul(1u64 << shift)).min(MAILBOX_TRANSPORT_MAX_RETRY_MS);
        state.next_attempt_at_ms = Some(now_ms.saturating_add(retry_after_ms));
        let degraded = mailbox_transport_is_degraded(state.failures);
        MailboxTransportFailureOutcome {
            failures: state.failures,
            next_retry_after_ms: retry_after_ms,
            should_log: degraded
                && (state.failures == MAILBOX_TRANSPORT_DEGRADED_FAILURE_THRESHOLD
                    || state.failures.is_power_of_two()),
            degraded,
        }
    }

    pub fn observe_member_profile(
        &mut self,
        group_id: &str,
        profile: GroupMailboxMemberProfile,
    ) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(group_id) {
            if session.anonymous_group {
                return Ok(());
            }
            let changed = session
                .known_members
                .get(&profile.member_id)
                .map(|existing| existing != &profile)
                .unwrap_or(true);
            session
                .known_members
                .insert(profile.member_id.clone(), profile);
            if changed {
                return self.persist_to_disk();
            }
        }
        Ok(())
    }

    pub fn known_member_profile(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Option<GroupMailboxMemberProfile> {
        self.sessions
            .get(group_id)
            .and_then(|session| session.known_members.get(member_id).cloned())
    }

    pub fn remove_member_profile(&mut self, group_id: &str, member_id: &str) -> Result<bool> {
        let removed = match self.sessions.get_mut(group_id) {
            Some(session) => session.known_members.remove(member_id).is_some(),
            None => false,
        };
        if !removed {
            return Ok(false);
        }
        self.pending_handshake_offers.retain(|_, offer| {
            !(offer.group_id == group_id && offer.sender_member_id == member_id)
        });
        self.persist_to_disk()?;
        Ok(true)
    }

    pub fn resolve_identified_handshake_target(
        &self,
        member_id: &str,
    ) -> Result<(GroupMailboxSession, GroupMailboxMemberProfile)> {
        let normalized_member_id = Self::normalize_member_selector(member_id);
        let mut matches = self
            .sessions
            .values()
            .filter(|session| !session.anonymous_group)
            .filter_map(|session| {
                session
                    .known_members
                    .get(&normalized_member_id)
                    .cloned()
                    .map(|profile| (session.clone(), profile))
            })
            .collect::<Vec<_>>();
        match matches.len() {
            0 => bail!(
                "No identified mailbox group knows member {} yet. Ask them to join or send a mailbox message first.",
                member_id
            ),
            1 => Ok(matches.swap_remove(0)),
            _ => bail!(
                "Member {} appears in multiple identified groups. Narrow the target after we add group-scoped /invite_h.",
                member_id
            ),
        }
    }

    pub fn resolve_identified_handshake_target_in_group(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<(GroupMailboxSession, GroupMailboxMemberProfile)> {
        let normalized_member_id = Self::normalize_member_selector(member_id);
        let Some(session) = self.sessions.get(group_id) else {
            bail!("Mailbox group {} is not joined locally.", group_id);
        };
        if session.anonymous_group {
            bail!("Anonymous mailbox groups do not support direct handshake offers");
        }
        let Some(profile) = session.known_members.get(&normalized_member_id).cloned() else {
            bail!(
                "Mailbox group {} does not know member {} yet.",
                group_id,
                member_id
            );
        };
        Ok((session.clone(), profile))
    }

    pub fn resolve_owner_kick_target(
        &self,
        member_id: &str,
    ) -> Result<(GroupMailboxSession, GroupMailboxMemberProfile)> {
        let normalized_member_id = Self::normalize_member_selector(member_id);
        let mut matches = self
            .sessions
            .values()
            .filter(|session| !session.anonymous_group)
            .filter(|session| session.local_member_id.is_some())
            .filter(|session| session.owner_member_id == session.local_member_id)
            .filter_map(|session| {
                session
                    .known_members
                    .get(&normalized_member_id)
                    .cloned()
                    .map(|profile| (session.clone(), profile))
            })
            .collect::<Vec<_>>();
        match matches.len() {
            0 => bail!(
                "No owner-controlled mailbox group knows member {} yet.",
                member_id
            ),
            1 => {
                let (session, profile) = matches.swap_remove(0);
                if Some(profile.member_id.as_str()) == session.local_member_id.as_deref() {
                    bail!("Group owner cannot remove themselves");
                }
                Ok((session, profile))
            }
            _ => bail!(
                "Member {} appears in multiple owner-controlled groups. Add group-scoped kick before using this selector.",
                member_id
            ),
        }
    }

    pub fn resolve_owner_disband_group(&self, group_id: &str) -> Result<GroupMailboxSession> {
        let Some(session) = self.get_cloned(group_id) else {
            bail!("Mailbox group {} is not joined", group_id);
        };
        let locally_owned = session.owner_special_id.is_some()
            || (session.local_member_id.is_some()
                && session.owner_member_id == session.local_member_id);
        if !locally_owned {
            bail!("Only the mailbox group owner may use /disband");
        }
        Ok(session)
    }

    pub fn resolve_owner_access_control_group(
        &self,
        group_id: &str,
    ) -> Result<GroupMailboxSession> {
        let Some(session) = self.get_cloned(group_id) else {
            bail!("Mailbox group {} is not joined", group_id);
        };
        if session.anonymous_group {
            bail!("Anonymous mailbox groups do not support /lock_g or /unlock_g");
        }
        let locally_owned = session.owner_special_id.is_some()
            || (session.local_member_id.is_some()
                && session.owner_member_id == session.local_member_id);
        if !locally_owned {
            bail!("Only the mailbox group owner may use /lock_g or /unlock_g");
        }
        Ok(session)
    }

    pub fn resolve_leave_group(&self, group_id: &str) -> Result<GroupMailboxSession> {
        let Some(session) = self.get_cloned(group_id) else {
            bail!("Mailbox group {} is not joined", group_id);
        };
        let locally_owned = session.owner_special_id.is_some()
            || (session.local_member_id.is_some()
                && session.owner_member_id == session.local_member_id);
        if locally_owned {
            bail!("Group owner must use /disband instead of /leave_g");
        }
        Ok(session)
    }

    pub(crate) fn chunk_downloads(&self) -> Vec<GroupChunkDownloadState> {
        let mut downloads = self.chunk_downloads.values().cloned().collect::<Vec<_>>();
        downloads.sort_by(|a, b| a.transfer_id.cmp(&b.transfer_id));
        downloads
    }

    pub(crate) fn chunk_download_exists(&self, transfer_id: &str) -> bool {
        self.chunk_downloads.contains_key(transfer_id)
    }

    pub(crate) fn upsert_chunk_download(
        &mut self,
        download: GroupChunkDownloadState,
    ) -> Result<()> {
        self.chunk_downloads
            .insert(download.transfer_id.clone(), download);
        self.persist_to_disk()
    }

    pub(crate) fn remove_chunk_download(&mut self, transfer_id: &str) -> Result<()> {
        if let Some(download) = self.chunk_downloads.remove(transfer_id) {
            secure_wipe_dir(&download.recv.temp_dir);
            return self.persist_to_disk();
        }
        Ok(())
    }

    pub fn remove_group(&mut self, group_id: &str) -> Result<Option<GroupMailboxSession>> {
        self.remove_group_with_tombstone_state(group_id, false)
    }

    pub fn remove_group_as_disbanded(
        &mut self,
        group_id: &str,
    ) -> Result<Option<GroupMailboxSession>> {
        self.remove_group_with_tombstone_state(group_id, true)
    }

    pub(crate) fn remove_group_with_tombstone_state(
        &mut self,
        group_id: &str,
        disbanded: bool,
    ) -> Result<Option<GroupMailboxSession>> {
        let removed = self.sessions.remove(group_id);
        if removed.is_none() {
            return Ok(None);
        }
        if let Some(session) = removed.as_ref() {
            self.tombstones.insert(
                session.group_id.clone(),
                GroupMailboxTombstone::from_session_with_flags(session, disbanded),
            );
        }
        let orphaned_downloads = self
            .chunk_downloads
            .iter()
            .filter(|(_, download)| download.group_id == group_id)
            .map(|(transfer_id, _)| transfer_id.clone())
            .collect::<Vec<_>>();
        for transfer_id in orphaned_downloads {
            if let Some(download) = self.chunk_downloads.remove(&transfer_id) {
                secure_wipe_dir(&download.recv.temp_dir);
            }
        }
        self.pending_file_offers
            .retain(|_, offer| offer.group_id != group_id);
        self.pending_handshake_offers
            .retain(|_, offer| offer.group_id != group_id);
        self.pending_fast_file_offers
            .retain(|_, offer| offer.group_id != group_id);
        let staged_fast_transfer_ids = self
            .staged_fast_file_transfers
            .iter()
            .filter(|(_, transfer)| transfer.group_id == group_id)
            .map(|(transfer_id, _)| transfer_id.clone())
            .collect::<Vec<_>>();
        for transfer_id in staged_fast_transfer_ids {
            let _ = self.clear_staged_fast_file_transfer(&transfer_id);
        }
        self.pending_fast_file_grants
            .retain(|_, grant| grant.group_id != group_id);
        self.mailbox_transport_backoff.remove(group_id);
        self.mailbox_manual_refresh_at.remove(group_id);
        self.persist_to_disk()?;
        Ok(removed)
    }

    pub fn pending_file_offers(&self) -> Vec<GroupPendingFileOfferSummary> {
        let mut offers = self
            .pending_file_offers
            .values()
            .map(|offer| GroupPendingFileOfferSummary {
                manifest_id: offer.manifest_id.clone(),
                group_id: offer.group_id.clone(),
                group_name: offer.group_name.clone(),
                anonymous_group: offer.anonymous_group,
                sender_member_id: offer.sender_member_id.clone(),
                filename: offer.manifest.filename.clone(),
                size_bytes: offer.manifest.size_bytes,
            })
            .collect::<Vec<_>>();
        offers.sort_by(|a, b| {
            a.group_id
                .cmp(&b.group_id)
                .then_with(|| a.manifest_id.cmp(&b.manifest_id))
        });
        offers
    }

    pub(crate) fn pending_handshake_offers(&self) -> Vec<GroupPendingHandshakeOfferSummary> {
        let now_ms = current_unix_ts_ms();
        let mut offers = self
            .pending_handshake_offers
            .values()
            .filter(|offer| offer.expires_at_ms > now_ms)
            .map(|offer| GroupPendingHandshakeOfferSummary {
                sender_member_id: offer.sender_member_id.clone(),
                group_id: offer.group_id.clone(),
                group_name: offer.group_name.clone(),
                received_at_ms: offer.received_at_ms,
                expires_at_ms: offer.expires_at_ms,
            })
            .collect::<Vec<_>>();
        offers.sort_by(|a, b| {
            a.received_at_ms
                .cmp(&b.received_at_ms)
                .then_with(|| a.sender_member_id.cmp(&b.sender_member_id))
        });
        offers
    }

    pub(crate) fn pending_fast_file_offers(&self) -> Vec<GroupPendingFastFileOfferSummary> {
        let mut offers = self
            .pending_fast_file_offers
            .values()
            .map(|offer| GroupPendingFastFileOfferSummary {
                transfer_id: offer.transfer_id.clone(),
                manifest_id: offer.manifest_id.clone(),
                group_id: offer.group_id.clone(),
                group_name: offer.group_name.clone(),
                anonymous_group: offer.anonymous_group,
                sender_member_id: offer.sender_member_id.clone(),
                filename: offer.offer.filename.clone(),
                size_bytes: offer.offer.size_bytes,
                relay_only: offer.offer.relay_only,
            })
            .collect::<Vec<_>>();
        offers.sort_by(|a, b| {
            a.group_id
                .cmp(&b.group_id)
                .then_with(|| a.transfer_id.cmp(&b.transfer_id))
        });
        offers
    }

    pub(crate) fn pending_file_offer_exists(&self, manifest_id: &str) -> bool {
        self.pending_file_offers.contains_key(manifest_id)
    }

    pub(crate) fn pending_fast_file_offer_exists(&self, transfer_id: &str) -> bool {
        self.pending_fast_file_offers.contains_key(transfer_id)
    }

    pub(crate) fn store_pending_file_offer(
        &mut self,
        offer: GroupPendingFileOffer,
    ) -> Result<bool> {
        if self.pending_file_offer_exists(&offer.manifest_id) {
            return Ok(false);
        }
        self.pending_file_offers
            .insert(offer.manifest_id.clone(), offer);
        self.persist_to_disk()?;
        Ok(true)
    }

    pub(crate) fn prune_expired_pending_handshake_offers(&mut self, now_ms: u64) -> Result<bool> {
        let before = self.pending_handshake_offers.len();
        self.pending_handshake_offers
            .retain(|_, offer| offer.expires_at_ms > now_ms);
        let changed = before != self.pending_handshake_offers.len();
        if changed {
            self.persist_to_disk()?;
        }
        Ok(changed)
    }

    pub(crate) fn store_pending_handshake_offer(
        &mut self,
        offer: GroupPendingHandshakeOffer,
    ) -> Result<bool> {
        self.prune_expired_pending_handshake_offers(current_unix_ts_ms())?;
        let changed = match self.pending_handshake_offers.get(&offer.sender_member_id) {
            Some(existing) if existing == &offer => false,
            _ => true,
        };
        if !changed {
            return Ok(false);
        }
        self.pending_handshake_offers
            .insert(offer.sender_member_id.clone(), offer);
        self.persist_to_disk()?;
        Ok(true)
    }

    pub(crate) fn prune_expired_fast_file_state(&mut self, now: u64) {
        let expired_transfer_ids = self
            .staged_fast_file_transfers
            .iter()
            .filter(|(transfer_id, transfer)| {
                transfer.expires_at <= now
                    && self
                        .active_fast_file_sender_refs
                        .get(*transfer_id)
                        .copied()
                        .unwrap_or(0)
                        == 0
            })
            .map(|(transfer_id, transfer)| (transfer_id.clone(), transfer.packed_path.clone()))
            .collect::<Vec<_>>();

        let mut expired_transfer_id_set = HashSet::new();
        for (transfer_id, packed_path) in expired_transfer_ids {
            expired_transfer_id_set.insert(transfer_id.clone());
            self.staged_fast_file_transfers.remove(&transfer_id);
            secure_wipe_file(&packed_path);
        }

        self.pending_fast_file_grants.retain(|_, grant| {
            grant.expires_at > now
                && !expired_transfer_id_set.contains(&grant.transfer_id)
                && self
                    .staged_fast_file_transfers
                    .get(&grant.transfer_id)
                    .map(|transfer| transfer.expires_at > now)
                    .unwrap_or(true)
        });
        self.pending_fast_file_offers.retain(|_, offer| {
            offer.offer.expires_at > now
                && !expired_transfer_id_set.contains(&offer.transfer_id)
                && self
                    .staged_fast_file_transfers
                    .get(&offer.transfer_id)
                    .map(|transfer| transfer.expires_at > now)
                    .unwrap_or(true)
        });
        self.active_fast_file_sender_refs
            .retain(|transfer_id, refs| {
                *refs > 0 && self.staged_fast_file_transfers.contains_key(transfer_id)
            });
    }

    pub(crate) fn store_pending_fast_file_offer(
        &mut self,
        offer: GroupPendingFastFileOffer,
    ) -> bool {
        self.prune_expired_fast_file_state(current_unix_ts());
        if self.pending_fast_file_offer_exists(&offer.transfer_id) {
            return false;
        }
        self.pending_fast_file_offers
            .insert(offer.transfer_id.clone(), offer);
        true
    }

    pub(crate) fn stage_fast_file_transfer(&mut self, transfer: GroupStagedFastFileTransfer) {
        self.prune_expired_fast_file_state(current_unix_ts());
        self.staged_fast_file_transfers
            .insert(transfer.transfer_id.clone(), transfer);
    }

    pub(crate) fn staged_fast_file_transfer_cloned(
        &self,
        transfer_id: &str,
    ) -> Option<GroupStagedFastFileTransfer> {
        self.staged_fast_file_transfers.get(transfer_id).cloned()
    }

    pub(crate) fn clear_staged_fast_file_transfer(
        &mut self,
        transfer_id: &str,
    ) -> Option<GroupStagedFastFileTransfer> {
        let removed = self.staged_fast_file_transfers.remove(transfer_id);
        self.active_fast_file_sender_refs.remove(transfer_id);
        if let Some(transfer) = removed.as_ref() {
            secure_wipe_file(&transfer.packed_path);
        }
        removed
    }

    pub(crate) fn track_fast_file_grant(&mut self, grant: GroupFastFileGrantState) {
        self.prune_expired_fast_file_state(current_unix_ts());
        self.pending_fast_file_grants.insert(
            fast_file_grant_state_key(&grant.transfer_id, &grant.recipient_member_id),
            grant,
        );
    }

    pub(crate) fn clear_fast_file_grants_for_transfer(&mut self, transfer_id: &str) {
        self.prune_expired_fast_file_state(current_unix_ts());
        self.pending_fast_file_grants
            .retain(|_, grant| grant.transfer_id != transfer_id);
    }

    pub(crate) fn clear_fast_file_grant_for_recipient(
        &mut self,
        transfer_id: &str,
        recipient_member_id: &str,
    ) -> Option<GroupFastFileGrantState> {
        self.prune_expired_fast_file_state(current_unix_ts());
        self.pending_fast_file_grants
            .remove(&fast_file_grant_state_key(transfer_id, recipient_member_id))
    }

    pub(crate) fn clear_fast_file_transfer(
        &mut self,
        transfer_id: &str,
    ) -> Option<GroupStagedFastFileTransfer> {
        self.prune_expired_fast_file_state(current_unix_ts());
        self.pending_fast_file_grants
            .retain(|_, grant| grant.transfer_id != transfer_id);
        self.pending_fast_file_offers.remove(transfer_id);
        if self
            .active_fast_file_sender_refs
            .get(transfer_id)
            .copied()
            .unwrap_or(0)
            > 0
        {
            return None;
        }
        self.clear_staged_fast_file_transfer(transfer_id)
    }

    pub(crate) fn mark_staged_fast_file_transfer_active(&mut self, transfer_id: &str) {
        self.prune_expired_fast_file_state(current_unix_ts());
        *self
            .active_fast_file_sender_refs
            .entry(transfer_id.to_string())
            .or_insert(0) += 1;
    }

    pub(crate) fn mark_staged_fast_file_transfer_inactive(&mut self, transfer_id: &str) {
        if let Some(refs) = self.active_fast_file_sender_refs.get_mut(transfer_id) {
            if *refs > 1 {
                *refs -= 1;
            } else {
                self.active_fast_file_sender_refs.remove(transfer_id);
            }
        }
        self.prune_expired_fast_file_state(current_unix_ts());
    }

    pub(crate) fn prune_expired_fast_file_state_now(&mut self) {
        self.prune_expired_fast_file_state(current_unix_ts());
    }

    pub(crate) fn due_pending_fast_file_grants_for_local_member(
        &mut self,
        local_member_id: &str,
        now: u64,
    ) -> Vec<GroupPendingFastFileGrantLaunch> {
        self.prune_expired_fast_file_state(now);
        self.pending_fast_file_grants
            .values()
            .filter(|grant| {
                grant.recipient_member_id == local_member_id
                    && grant.expires_at > now
                    && matches!(grant.envelope, GroupFastFileGrantEnvelope::Grant(_))
                    && grant.secret.is_some()
            })
            .filter_map(|grant| {
                let GroupFastFileGrantEnvelope::Grant(payload) = &grant.envelope else {
                    return None;
                };
                let secret = grant.secret.clone()?;
                Some(GroupPendingFastFileGrantLaunch {
                    transfer_id: secret.transfer_id.clone(),
                    group_id: secret.group_id.clone(),
                    sender_member_id: payload.sender_member_id.clone(),
                    sender_verifying_key_hex: payload.sender_verifying_key_hex.clone(),
                    secret,
                })
            })
            .collect()
    }

    pub(crate) fn due_pending_fast_file_grants(
        &mut self,
        now: u64,
    ) -> Vec<GroupPendingFastFileGrantLaunch> {
        self.prune_expired_fast_file_state(now);
        let local_member_ids = self
            .sessions
            .values()
            .filter_map(|session| session.local_member_id.clone())
            .collect::<HashSet<_>>();
        let mut launches = Vec::new();
        for local_member_id in local_member_ids {
            launches
                .extend(self.due_pending_fast_file_grants_for_local_member(&local_member_id, now));
        }
        launches.sort_by(|a, b| {
            a.group_id
                .cmp(&b.group_id)
                .then_with(|| a.transfer_id.cmp(&b.transfer_id))
        });
        launches
    }

    pub(crate) fn mark_fast_file_grant_launched(
        &mut self,
        transfer_id: &str,
        recipient_member_id: &str,
    ) {
        self.pending_fast_file_grants
            .remove(&fast_file_grant_state_key(transfer_id, recipient_member_id));
    }

    pub(crate) fn take_pending_fast_file_grants_for_local_member(
        &mut self,
        local_member_id: &str,
        now: u64,
    ) -> Vec<GroupPendingFastFileGrantLaunch> {
        self.prune_expired_fast_file_state(now);
        let matching_keys = self
            .pending_fast_file_grants
            .iter()
            .filter(|(_, grant)| {
                grant.recipient_member_id == local_member_id
                    && grant.expires_at > now
                    && matches!(grant.envelope, GroupFastFileGrantEnvelope::Grant(_))
                    && grant.secret.is_some()
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut launches = Vec::new();
        for key in matching_keys {
            let Some(grant) = self.pending_fast_file_grants.remove(&key) else {
                continue;
            };
            let GroupFastFileGrantEnvelope::Grant(payload) = &grant.envelope else {
                continue;
            };
            let Some(secret) = grant.secret else {
                continue;
            };
            launches.push(GroupPendingFastFileGrantLaunch {
                transfer_id: secret.transfer_id.clone(),
                group_id: secret.group_id.clone(),
                sender_member_id: payload.sender_member_id.clone(),
                sender_verifying_key_hex: payload.sender_verifying_key_hex.clone(),
                secret,
            });
        }
        launches
    }

    pub(crate) fn fast_file_grant_state_cloned(
        &self,
        transfer_id: &str,
        recipient_member_id: &str,
    ) -> Option<GroupFastFileGrantState> {
        self.pending_fast_file_grants
            .get(&fast_file_grant_state_key(transfer_id, recipient_member_id))
            .cloned()
    }

    pub(crate) fn fast_transfer_open_authorization(
        &mut self,
        transfer_id: &str,
        recipient_member_id: &str,
        now: u64,
    ) -> Option<(GroupStagedFastFileTransfer, GroupFastFileGrantSecret)> {
        self.prune_expired_fast_file_state(now);
        let staged = self.staged_fast_file_transfer_cloned(transfer_id)?;
        if staged.expires_at <= now {
            return None;
        }
        let grant = self.fast_file_grant_state_cloned(transfer_id, recipient_member_id)?;
        if grant.expires_at <= now {
            return None;
        }
        let secret = grant.secret?;
        Some((staged, secret))
    }

    pub(crate) fn consume_fast_transfer_open_authorization(
        &mut self,
        transfer_id: &str,
        recipient_member_id: &str,
        now: u64,
    ) -> Option<(GroupStagedFastFileTransfer, GroupFastFileGrantSecret)> {
        self.prune_expired_fast_file_state(now);
        let staged = self.staged_fast_file_transfer_cloned(transfer_id)?;
        if staged.expires_at <= now {
            return None;
        }
        let grant = self
            .pending_fast_file_grants
            .remove(&fast_file_grant_state_key(transfer_id, recipient_member_id))?;
        if grant.expires_at <= now {
            return None;
        }
        let secret = grant.secret?;
        Some((staged, secret))
    }

    pub(crate) fn drop_fast_file_offer(&mut self, transfer_id: &str) {
        self.prune_expired_fast_file_state(current_unix_ts());
        self.pending_fast_file_offers.remove(transfer_id);
    }

    pub(crate) fn remove_chunk_download_by_transfer_id(&mut self, transfer_id: &str) -> Result<()> {
        self.remove_chunk_download(transfer_id)
    }

    pub(crate) fn pending_file_offer_cloned_for_selector(
        &self,
        selector: &str,
    ) -> Result<Option<GroupPendingFileOffer>> {
        if let Some(offer) = self.pending_file_offers.get(selector) {
            return Ok(Some(offer.clone()));
        }
        let mut matches = self
            .pending_file_offers
            .values()
            .filter(|offer| offer.group_id == selector)
            .cloned()
            .collect::<Vec<_>>();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.pop()),
            _ => {
                let mut manifest_ids = matches
                    .into_iter()
                    .map(|offer| offer.manifest_id)
                    .collect::<Vec<_>>();
                manifest_ids.sort();
                bail!(
                    "Group {} has multiple pending file offers. Use /accept <manifest_id> or /reject <manifest_id>. Pending manifests: {}",
                    selector,
                    manifest_ids.join(", ")
                );
            }
        }
    }

    pub(crate) fn take_pending_handshake_offer_for_selector(
        &mut self,
        selector: &str,
    ) -> Result<Option<GroupPendingHandshakeOffer>> {
        self.prune_expired_pending_handshake_offers(current_unix_ts_ms())?;
        let normalized_selector = Self::normalize_member_selector(selector);
        let removed = self.pending_handshake_offers.remove(&normalized_selector);
        if removed.is_some() {
            self.persist_to_disk()?;
        }
        Ok(removed)
    }

    pub(crate) fn take_single_pending_handshake_offer(
        &mut self,
    ) -> Result<Option<GroupPendingHandshakeOffer>> {
        self.prune_expired_pending_handshake_offers(current_unix_ts_ms())?;
        if self.pending_handshake_offers.len() != 1 {
            return Ok(None);
        }
        let sender_member_id = self
            .pending_handshake_offers
            .keys()
            .next()
            .cloned()
            .expect("pending handshake offer count checked");
        let removed = self.pending_handshake_offers.remove(&sender_member_id);
        if removed.is_some() {
            self.persist_to_disk()?;
        }
        Ok(removed)
    }

    pub(crate) fn drain_pending_handshake_offers(
        &mut self,
    ) -> Result<Vec<GroupPendingHandshakeOffer>> {
        self.prune_expired_pending_handshake_offers(current_unix_ts_ms())?;
        if self.pending_handshake_offers.is_empty() {
            return Ok(Vec::new());
        }
        let drained = self
            .pending_handshake_offers
            .drain()
            .map(|(_, offer)| offer)
            .collect();
        self.persist_to_disk()?;
        Ok(drained)
    }

    pub(crate) fn remove_pending_file_offer(
        &mut self,
        manifest_id: &str,
    ) -> Result<Option<GroupPendingFileOffer>> {
        let removed = self.pending_file_offers.remove(manifest_id);
        if removed.is_some() {
            self.persist_to_disk()?;
        }
        Ok(removed)
    }

    pub(crate) fn persisted_sessions(&self) -> Vec<PersistedGroupMailboxSession> {
        let mut sessions = self
            .sessions
            .values()
            .filter(|session| session.persistence == GroupMailboxPersistence::EncryptedDisk)
            .map(PersistedGroupMailboxSession::from_session)
            .collect::<Vec<_>>();
        sessions.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        sessions
    }

    pub(crate) fn persisted_tombstones(&self) -> Vec<PersistedGroupMailboxTombstone> {
        let mut tombstones = self
            .tombstones
            .values()
            .map(PersistedGroupMailboxTombstone::from_tombstone)
            .collect::<Vec<_>>();
        tombstones.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        tombstones
    }

    pub(crate) fn persisted_chunk_downloads(&self) -> Vec<GroupChunkDownloadState> {
        let mut downloads = self
            .chunk_downloads
            .values()
            .filter(|download| download.persistence == GroupMailboxPersistence::EncryptedDisk)
            .cloned()
            .collect::<Vec<_>>();
        downloads.sort_by(|a, b| a.transfer_id.cmp(&b.transfer_id));
        downloads
    }

    pub(crate) fn persisted_pending_file_offers(&self) -> Vec<GroupPendingFileOffer> {
        let mut offers = self
            .pending_file_offers
            .values()
            .filter(|offer| offer.persistence == GroupMailboxPersistence::EncryptedDisk)
            .cloned()
            .collect::<Vec<_>>();
        offers.sort_by(|a, b| a.manifest_id.cmp(&b.manifest_id));
        offers
    }

    pub(crate) fn persisted_pending_handshake_offers(&self) -> Vec<GroupPendingHandshakeOffer> {
        let now_ms = current_unix_ts_ms();
        let mut offers = self
            .pending_handshake_offers
            .values()
            .filter(|offer| offer.persistence == GroupMailboxPersistence::EncryptedDisk)
            .filter(|offer| offer.expires_at_ms > now_ms)
            .cloned()
            .collect::<Vec<_>>();
        offers.sort_by(|a, b| {
            a.received_at_ms
                .cmp(&b.received_at_ms)
                .then_with(|| a.sender_member_id.cmp(&b.sender_member_id))
        });
        offers
    }

    pub(crate) fn persist_to_disk(&self) -> Result<()> {
        let path = match &self.persist_path {
            Some(path) => path,
            None => return Ok(()),
        };
        let key = match &self.persist_key {
            Some(key) => key,
            None => return Ok(()),
        };
        for session in self
            .sessions
            .values()
            .filter(|session| session.persistence == GroupMailboxPersistence::EncryptedDisk)
        {
            validate_group_mailbox_session(session)?;
        }

        let registry = PersistedGroupMailboxRegistry {
            version: 1,
            sessions: self.persisted_sessions(),
            tombstones: self.persisted_tombstones(),
            chunk_downloads: self.persisted_chunk_downloads(),
            pending_file_offers: self.persisted_pending_file_offers(),
            pending_handshake_offers: self.persisted_pending_handshake_offers(),
        };
        if registry.sessions.is_empty()
            && registry.tombstones.is_empty()
            && registry.chunk_downloads.is_empty()
            && registry.pending_file_offers.is_empty()
            && registry.pending_handshake_offers.is_empty()
        {
            if path.exists() {
                secure_wipe_file(path);
            }
            return Ok(());
        }

        let mut plaintext = bincode::serialize(&registry)
            .context("Failed to encode persisted mailbox group registry")?;
        let nonce: [u8; 32] = rand::random();
        let aegis = Aegis256::<32>::new(key, &nonce);
        let (ciphertext, tag) = aegis.encrypt(&plaintext, b"group-mailboxes-persist-v1");
        plaintext.zeroize();
        let mut ciphertext_with_tag = ciphertext;
        ciphertext_with_tag.extend_from_slice(&tag);
        let blob = PersistedGroupMailboxBlob {
            version: 1,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext_with_tag,
        };
        let encoded =
            bincode::serialize(&blob).context("Failed to encode persisted mailbox group blob")?;

        crate::crypto::keystore::write_private_file(path, &encoded).with_context(|| {
            format!(
                "Failed to persist mailbox group state file {}",
                path.display()
            )
        })?;
        Ok(())
    }
}

impl PersistedGroupMailboxSession {
    pub(crate) fn from_session(session: &GroupMailboxSession) -> Self {
        let mut known_members = session.known_members.values().cloned().collect::<Vec<_>>();
        known_members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Self {
            group_id: session.group_id.clone(),
            group_name: session.group_name.clone(),
            anonymous_group: session.anonymous_group,
            join_locked: session.join_locked,
            mailbox_descriptor: session.mailbox_descriptor.clone(),
            mailbox_capability: session.mailbox_capability.clone(),
            content_crypto_state: session.content_crypto_state.clone(),
            anonymous_writer_state: session.anonymous_writer_state.clone(),
            local_member_id: session.local_member_id.clone(),
            owner_member_id: session.owner_member_id.clone(),
            joined_at: session.joined_at,
            invite_id: session.invite_id.clone(),
            owner_special_id: session.owner_special_id.clone(),
            mailbox_epoch: session.mailbox_epoch,
            poll_cursor: session.poll_cursor.clone(),
            known_members,
            join_bridge_handles: session.join_bridge_handles.clone(),
        }
    }

    pub(crate) fn into_session(self) -> Result<GroupMailboxSession> {
        let known_members = self
            .known_members
            .into_iter()
            .map(|profile| (profile.member_id.clone(), profile))
            .collect::<HashMap<_, _>>();
        let session = GroupMailboxSession {
            group_id: self.group_id,
            group_name: self.group_name,
            anonymous_group: self.anonymous_group,
            join_locked: self.join_locked,
            mailbox_descriptor: self.mailbox_descriptor,
            mailbox_capability: self.mailbox_capability,
            content_crypto_state: self.content_crypto_state,
            anonymous_writer_state: self.anonymous_writer_state,
            local_member_id: self.local_member_id,
            owner_member_id: self.owner_member_id,
            persistence: GroupMailboxPersistence::EncryptedDisk,
            joined_at: self.joined_at,
            invite_id: self.invite_id,
            owner_special_id: self.owner_special_id,
            mailbox_epoch: self.mailbox_epoch,
            poll_cursor: self.poll_cursor,
            next_cover_traffic_at: None,
            last_real_activity_at: None,
            known_members,
            local_posted_message_ids: HashSet::new(),
            seen_message_ids: HashMap::new(),
            join_bridge_handles: self.join_bridge_handles,
        };
        validate_group_mailbox_session(&session)?;
        Ok(session)
    }
}

impl GroupMailboxTombstone {
    pub(crate) fn from_session_with_flags(session: &GroupMailboxSession, disbanded: bool) -> Self {
        Self {
            group_id: session.group_id.clone(),
            mailbox_epoch: session.mailbox_epoch,
            join_locked: session.join_locked,
            disbanded,
            left_at: current_unix_ts(),
        }
    }
}

impl PersistedGroupMailboxTombstone {
    pub(crate) fn from_tombstone(tombstone: &GroupMailboxTombstone) -> Self {
        Self {
            group_id: tombstone.group_id.clone(),
            mailbox_epoch: tombstone.mailbox_epoch,
            join_locked: tombstone.join_locked,
            disbanded: tombstone.disbanded,
            left_at: tombstone.left_at,
        }
    }

    pub(crate) fn into_tombstone(self) -> Result<GroupMailboxTombstone> {
        if self.group_id.trim().is_empty() {
            bail!("Persisted mailbox tombstone is missing group_id");
        }
        Ok(GroupMailboxTombstone {
            group_id: self.group_id,
            mailbox_epoch: self.mailbox_epoch,
            join_locked: self.join_locked,
            disbanded: self.disbanded,
            left_at: self.left_at,
        })
    }
}

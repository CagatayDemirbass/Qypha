use std::collections::{HashMap, HashSet, VecDeque};

use crate::network::protocol::{AgentRequest, MessageKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncomingTransferPolicy {
    AskEveryTime,
    AlwaysAccept,
}

#[derive(Debug, Clone)]
pub(crate) enum PendingTransferKind {
    File {
        filename: String,
        encrypted_size: u64,
    },
    ChunkInit {
        session_id: String,
        total_chunks: usize,
        sealed_v2: bool,
        filename_hint: Option<String>,
        total_size_hint: Option<u64>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct PendingIncomingTransfer {
    pub(crate) peer_id: libp2p::PeerId,
    pub(crate) sender_did: String,
    pub(crate) sender_name: String,
    pub(crate) request: AgentRequest,
    pub(crate) decision_key: String,
    pub(crate) kind: PendingTransferKind,
}

#[derive(Default)]
pub(crate) struct TransferDecisionState {
    sender_policies: HashMap<String, IncomingTransferPolicy>,
    pending_by_sender: HashMap<String, VecDeque<PendingIncomingTransfer>>,
    pending_keys: HashSet<String>,
    approved_keys: HashSet<String>,
    pending_chunk_sessions: HashSet<String>,
    rejected_chunk_sessions: HashSet<String>,
}

impl TransferDecisionState {
    pub(crate) fn policy_for_sender(&self, sender_did: &str) -> IncomingTransferPolicy {
        self.sender_policies
            .get(sender_did)
            .copied()
            .unwrap_or(IncomingTransferPolicy::AskEveryTime)
    }

    pub(crate) fn set_policy(&mut self, sender_did: &str, policy: IncomingTransferPolicy) {
        self.sender_policies.insert(sender_did.to_string(), policy);
    }

    pub(crate) fn queue_pending(&mut self, pending: PendingIncomingTransfer) -> bool {
        if !self.pending_keys.insert(pending.decision_key.clone()) {
            return false;
        }
        if let PendingTransferKind::ChunkInit { session_id, .. } = &pending.kind {
            self.pending_chunk_sessions.insert(session_id.clone());
        }
        self.pending_by_sender
            .entry(pending.sender_did.clone())
            .or_default()
            .push_back(pending);
        true
    }

    pub(crate) fn take_one_for_sender(
        &mut self,
        sender_did: &str,
    ) -> Option<PendingIncomingTransfer> {
        let queue = self.pending_by_sender.get_mut(sender_did)?;
        let item = queue.pop_front()?;
        if queue.is_empty() {
            self.pending_by_sender.remove(sender_did);
        }
        self.pending_keys.remove(&item.decision_key);
        if let PendingTransferKind::ChunkInit { session_id, .. } = &item.kind {
            self.pending_chunk_sessions.remove(session_id);
        }
        Some(item)
    }

    pub(crate) fn take_all_for_sender(&mut self, sender_did: &str) -> Vec<PendingIncomingTransfer> {
        let Some(mut queue) = self.pending_by_sender.remove(sender_did) else {
            return vec![];
        };
        let mut out = Vec::with_capacity(queue.len());
        while let Some(item) = queue.pop_front() {
            self.pending_keys.remove(&item.decision_key);
            if let PendingTransferKind::ChunkInit { session_id, .. } = &item.kind {
                self.pending_chunk_sessions.remove(session_id);
            }
            out.push(item);
        }
        out
    }

    pub(crate) fn reject_one_for_sender(
        &mut self,
        sender_did: &str,
    ) -> Option<PendingIncomingTransfer> {
        let item = self.take_one_for_sender(sender_did)?;
        if let PendingTransferKind::ChunkInit { session_id, .. } = &item.kind {
            self.rejected_chunk_sessions.insert(session_id.clone());
        }
        Some(item)
    }

    pub(crate) fn consume_approved_key(&mut self, key: &str) -> bool {
        self.approved_keys.remove(key)
    }

    pub(crate) fn approve_key(&mut self, key: String) {
        self.approved_keys.insert(key);
    }

    pub(crate) fn is_pending_or_rejected_chunk_session(&self, session_id: &str) -> bool {
        self.pending_chunk_sessions.contains(session_id)
            || self.rejected_chunk_sessions.contains(session_id)
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.pending_by_sender.values().map(|q| q.len()).sum()
    }

    pub(crate) fn sender_name_for_did(&self, sender_did: &str) -> Option<String> {
        self.pending_by_sender
            .get(sender_did)
            .and_then(|q| q.front().map(|p| p.sender_name.clone()))
    }

    pub(crate) fn pending_senders_named(&self, selector: &str) -> Vec<(String, String)> {
        self.pending_by_sender
            .iter()
            .filter_map(|(did, queue)| {
                let front = queue.front()?;
                if front.sender_name.eq_ignore_ascii_case(selector) {
                    Some((did.clone(), front.sender_name.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn pending_transfers(&self) -> Vec<PendingIncomingTransfer> {
        self.pending_by_sender
            .values()
            .flat_map(|queue| queue.iter().cloned())
            .collect()
    }
}

pub(crate) fn transfer_decision_key(request: &AgentRequest) -> Option<String> {
    match request.msg_type {
        MessageKind::FileTransfer | MessageKind::ChunkTransferInit => Some(format!(
            "{:?}|{}|{}|{}|{}",
            request.msg_type,
            request.sender_did,
            request.nonce,
            request.timestamp,
            request.message_id
        )),
        _ => None,
    }
}

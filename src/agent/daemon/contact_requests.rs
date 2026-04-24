use std::collections::HashMap;

use libp2p::PeerId;

use crate::network::contact_did::decode_contact_did;
use crate::network::contact_request::ContactRequestPayload;
use crate::network::did_profile::DidProfile;
use crate::network::direct_invite_token::DirectInviteTransportPolicy;

#[derive(Debug, Clone)]
pub(crate) struct PendingContactRequest {
    pub(crate) peer_id: Option<PeerId>,
    pub(crate) request_id: String,
    pub(crate) sender_did: String,
    pub(crate) sender_name: String,
    pub(crate) sender_profile: DidProfile,
    pub(crate) intro_message: Option<String>,
    pub(crate) invite_token: Option<String>,
    pub(crate) transport_policy: DirectInviteTransportPolicy,
    pub(crate) created_at: u64,
}

#[derive(Debug, Default)]
pub(crate) struct ContactRequestRegistry {
    pending_by_did: HashMap<String, PendingContactRequest>,
}

impl ContactRequestRegistry {
    fn resolve_selector<'a>(selector: &'a str) -> std::borrow::Cow<'a, str> {
        if let Ok(resolved) = decode_contact_did(selector) {
            return std::borrow::Cow::Owned(resolved.canonical_did);
        }
        std::borrow::Cow::Borrowed(selector)
    }

    fn upsert_impl(
        &mut self,
        peer_id: Option<PeerId>,
        sender_name: String,
        payload: ContactRequestPayload,
    ) -> bool {
        let sender_did = payload.sender_profile.did.clone();
        let request = PendingContactRequest {
            peer_id,
            request_id: payload.request_id,
            sender_did: sender_did.clone(),
            sender_name,
            sender_profile: payload.sender_profile,
            intro_message: payload.intro_message,
            invite_token: payload.invite_token,
            transport_policy: payload.transport_policy,
            created_at: payload.created_at,
        };
        self.pending_by_did.insert(sender_did, request).is_none()
    }

    pub(crate) fn upsert_live(
        &mut self,
        peer_id: PeerId,
        sender_name: String,
        payload: ContactRequestPayload,
    ) -> bool {
        self.upsert_impl(Some(peer_id), sender_name, payload)
    }

    pub(crate) fn upsert_mailbox(
        &mut self,
        sender_name: String,
        payload: ContactRequestPayload,
    ) -> bool {
        self.upsert_impl(None, sender_name, payload)
    }

    pub(crate) fn get(&self, did: &str) -> Option<&PendingContactRequest> {
        self.pending_by_did.get(did)
    }

    pub(crate) fn get_by_selector(&self, selector: &str) -> Option<&PendingContactRequest> {
        let resolved = Self::resolve_selector(selector);
        self.pending_by_did.get(resolved.as_ref())
    }

    pub(crate) fn take(&mut self, did: &str) -> Option<PendingContactRequest> {
        self.pending_by_did.remove(did)
    }

    pub(crate) fn take_by_selector(&mut self, selector: &str) -> Option<PendingContactRequest> {
        let resolved = Self::resolve_selector(selector);
        self.pending_by_did.remove(resolved.as_ref())
    }

    pub(crate) fn len(&self) -> usize {
        self.pending_by_did.len()
    }

    pub(crate) fn clear_all(&mut self) -> usize {
        let cleared = self.pending_by_did.len();
        self.pending_by_did.clear();
        cleared
    }

    pub(crate) fn pending_cloned(&self) -> Vec<PendingContactRequest> {
        let mut items = self.pending_by_did.values().cloned().collect::<Vec<_>>();
        items.sort_by(|a, b| a.sender_did.cmp(&b.sender_did));
        items
    }

    pub(crate) fn single_pending_cloned(&self) -> Option<PendingContactRequest> {
        (self.pending_by_did.len() == 1)
            .then(|| self.pending_by_did.values().next().cloned())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::encode_contact_did;
    use crate::network::did_profile::DidProfile;

    fn sample_payload(keypair: &AgentKeyPair) -> ContactRequestPayload {
        ContactRequestPayload {
            version: 1,
            request_id: format!("req-{}", keypair.did),
            sender_profile: DidProfile::generate(keypair, Vec::new(), None),
            intro_message: Some("hello".to_string()),
            invite_token: None,
            transport_policy: DirectInviteTransportPolicy::Any,
            created_at: 1234,
            signature: vec![7; 64],
        }
    }

    #[test]
    fn upsert_replaces_existing_request_for_same_did() {
        let mut registry = ContactRequestRegistry::default();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let keypair = AgentKeyPair::generate("Alice", "agent");

        assert!(registry.upsert_live(peer_a, "Alice".to_string(), sample_payload(&keypair)));
        assert!(!registry.upsert_live(peer_b, "Alice New".to_string(), sample_payload(&keypair)));

        let stored = registry.get(&keypair.did).unwrap();
        assert_eq!(stored.peer_id, Some(peer_b));
        assert_eq!(stored.sender_name, "Alice New");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn take_removes_pending_request() {
        let mut registry = ContactRequestRegistry::default();
        let peer = PeerId::random();
        let keypair = AgentKeyPair::generate("Bob", "agent");
        registry.upsert_live(peer, "Bob".to_string(), sample_payload(&keypair));

        let removed = registry.take(&keypair.did).unwrap();
        assert_eq!(removed.sender_did, keypair.did);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn mailbox_origin_request_has_no_live_peer_binding() {
        let mut registry = ContactRequestRegistry::default();
        let keypair = AgentKeyPair::generate("Charlie", "agent");

        assert!(registry.upsert_mailbox("Charlie".to_string(), sample_payload(&keypair)));
        let stored = registry.get(&keypair.did).unwrap();
        assert_eq!(stored.peer_id, None);
    }

    #[test]
    fn get_by_selector_resolves_short_contact_did() {
        let mut registry = ContactRequestRegistry::default();
        let peer = PeerId::random();
        let keypair = AgentKeyPair::generate("Dana", "agent");
        let payload = sample_payload(&keypair);
        let short_did = encode_contact_did(&payload.sender_profile).unwrap();

        assert!(registry.upsert_live(peer, "Dana".to_string(), payload));
        let stored = registry.get_by_selector(&short_did).unwrap();
        assert_eq!(stored.sender_did, keypair.did);
    }

    #[test]
    fn take_by_selector_resolves_short_contact_did() {
        let mut registry = ContactRequestRegistry::default();
        let peer = PeerId::random();
        let keypair = AgentKeyPair::generate("Eve", "agent");
        let payload = sample_payload(&keypair);
        let short_did = encode_contact_did(&payload.sender_profile).unwrap();

        assert!(registry.upsert_live(peer, "Eve".to_string(), payload));
        let removed = registry.take_by_selector(&short_did).unwrap();
        assert_eq!(removed.sender_did, keypair.did);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn clear_all_removes_every_pending_request() {
        let mut registry = ContactRequestRegistry::default();
        let first = AgentKeyPair::generate("First", "agent");
        let second = AgentKeyPair::generate("Second", "agent");
        registry.upsert_mailbox("First".to_string(), sample_payload(&first));
        registry.upsert_mailbox("Second".to_string(), sample_payload(&second));

        assert_eq!(registry.clear_all(), 2);
        assert_eq!(registry.len(), 0);
    }
}

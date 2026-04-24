use anyhow::Result;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};

use super::peer::PeerInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupMemberRecord {
    pub(crate) did: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupInviteState {
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) invite_fp: String,
    pub(crate) created_at: u64,
    pub(crate) local_member_did: Option<String>,
    pub(crate) active_members: HashSet<String>,
    pub(crate) known_members: HashMap<String, String>,
    pub(crate) kicked_members: HashSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectedGroupSummary {
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) total_members: usize,
    pub(crate) linked_members: usize,
    pub(crate) members: Vec<GroupMemberRecord>,
}

#[derive(Debug, Default)]
pub(crate) struct GroupInviteRegistry {
    pub(crate) issued: HashMap<String, GroupInviteState>,
}

impl GroupInviteRegistry {
    pub(crate) fn upsert_group_invite(
        &mut self,
        group_id: &str,
        group_name: Option<&str>,
        invite_fp: String,
    ) {
        let normalized_name = group_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        self.issued
            .entry(group_id.to_string())
            .and_modify(|g| {
                g.invite_fp = invite_fp.clone();
                if normalized_name.is_some() {
                    g.group_name = normalized_name.clone();
                }
            })
            .or_insert_with(|| GroupInviteState {
                group_id: group_id.to_string(),
                group_name: normalized_name,
                invite_fp,
                created_at: chrono::Utc::now().timestamp() as u64,
                local_member_did: None,
                active_members: HashSet::new(),
                known_members: HashMap::new(),
                kicked_members: HashSet::new(),
            });
    }

    pub(crate) fn mark_local_member(&mut self, group_id: &str, did: &str, name: &str) {
        if let Some(group) = self.issued.get_mut(group_id) {
            group.local_member_did = Some(did.to_string());
            group
                .known_members
                .insert(did.to_string(), name.to_string());
        }
    }

    pub(crate) fn note_known_member(&mut self, group_id: &str, did: &str, name: &str) {
        if let Some(group) = self.issued.get_mut(group_id) {
            group
                .known_members
                .insert(did.to_string(), name.to_string());
        }
    }

    pub(crate) fn ensure_group_metadata(&mut self, group_id: &str, group_name: Option<&str>) {
        let normalized_name = group_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        self.issued
            .entry(group_id.to_string())
            .and_modify(|group| {
                if normalized_name.is_some() {
                    group.group_name = normalized_name.clone();
                }
            })
            .or_insert_with(|| GroupInviteState {
                group_id: group_id.to_string(),
                group_name: normalized_name,
                invite_fp: String::new(),
                created_at: chrono::Utc::now().timestamp() as u64,
                local_member_did: None,
                active_members: HashSet::new(),
                known_members: HashMap::new(),
                kicked_members: HashSet::new(),
            });
    }

    pub(crate) fn local_group_ids(&self) -> Vec<String> {
        let mut group_ids: Vec<String> = self
            .issued
            .values()
            .filter(|group| group.local_member_did.is_some())
            .map(|group| group.group_id.clone())
            .collect();
        group_ids.sort();
        group_ids
    }

    pub(crate) fn group_name(&self, group_id: &str) -> Option<String> {
        self.issued
            .get(group_id)
            .and_then(|group| group.group_name.clone())
    }

    pub(crate) fn is_known_member(&self, group_id: &str, did: &str) -> bool {
        self.issued
            .get(group_id)
            .is_some_and(|group| group.known_members.contains_key(did))
    }

    pub(crate) fn member_records(&self, group_id: &str) -> Vec<GroupMemberRecord> {
        let Some(group) = self.issued.get(group_id) else {
            return Vec::new();
        };
        let mut members: Vec<GroupMemberRecord> = group
            .known_members
            .iter()
            .map(|(did, name)| GroupMemberRecord {
                did: did.clone(),
                name: name.clone(),
            })
            .collect();
        members.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
        members
    }

    pub(crate) fn mark_member_joined(
        &mut self,
        group_id: &str,
        did: &str,
        name: &str,
    ) -> Result<(), &'static str> {
        let Some(group) = self.issued.get_mut(group_id) else {
            return Err("group_not_found");
        };
        if group.kicked_members.contains(did) {
            return Err("member_kicked");
        }
        group.active_members.insert(did.to_string());
        group
            .known_members
            .insert(did.to_string(), name.to_string());
        Ok(())
    }

    pub(crate) fn mark_member_left(&mut self, did: &str) {
        for group in self.issued.values_mut() {
            group.active_members.remove(did);
        }
    }

    pub(crate) fn kick_member(&mut self, did: &str) -> Option<String> {
        for group in self.issued.values_mut() {
            if group.active_members.contains(did) || group.kicked_members.contains(did) {
                group.active_members.remove(did);
                group.known_members.remove(did);
                group.kicked_members.insert(did.to_string());
                return Some(group.group_id.clone());
            }
        }
        None
    }

    pub(crate) fn connected_summaries(
        &self,
        peers: &DashMap<String, PeerInfo>,
    ) -> Vec<ConnectedGroupSummary> {
        let mut groups: Vec<ConnectedGroupSummary> = self
            .issued
            .values()
            .filter_map(|group| {
                let mut members: Vec<GroupMemberRecord> = group
                    .known_members
                    .iter()
                    .map(|(did, name)| GroupMemberRecord {
                        did: did.clone(),
                        name: name.clone(),
                    })
                    .collect();
                members.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
                let linked_members = peers
                    .iter()
                    .filter(|entry| {
                        let peer = entry.value();
                        !peer.did.is_empty() && group.known_members.contains_key(&peer.did)
                    })
                    .count();
                let total_members = members.len();
                if total_members == 0 && linked_members == 0 {
                    return None;
                }
                Some(ConnectedGroupSummary {
                    group_id: group.group_id.clone(),
                    group_name: group.group_name.clone(),
                    total_members,
                    linked_members,
                    members,
                })
            })
            .collect();
        groups.sort_by(|a, b| {
            a.group_name
                .as_deref()
                .unwrap_or(&a.group_id)
                .cmp(b.group_name.as_deref().unwrap_or(&b.group_id))
                .then_with(|| a.group_id.cmp(&b.group_id))
        });
        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_summaries_include_group_name_and_counts() {
        let mut registry = GroupInviteRegistry::default();
        let peers = DashMap::new();
        registry.upsert_group_invite("grp_ops", Some("Ops"), "fp-1".to_string());
        registry.mark_local_member("grp_ops", "did:nxf:local", "local");
        registry.note_known_member("grp_ops", "did:nxf:a", "alpha");
        registry.note_known_member("grp_ops", "did:nxf:b", "beta");
        peers.insert(
            "peer-a".to_string(),
            PeerInfo {
                peer_id: libp2p::PeerId::random(),
                did: "did:nxf:a".to_string(),
                name: "alpha".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerInfo {
                peer_id: libp2p::PeerId::random(),
                did: "did:nxf:b".to_string(),
                name: "beta".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        let summaries = registry.connected_summaries(&peers);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].group_id, "grp_ops");
        assert_eq!(summaries[0].group_name.as_deref(), Some("Ops"));
        assert_eq!(summaries[0].total_members, 3);
        assert_eq!(summaries[0].linked_members, 2);
    }
}

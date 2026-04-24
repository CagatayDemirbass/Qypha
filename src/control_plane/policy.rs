use std::sync::Arc;
use tokio::sync::RwLock;

use super::rbac::{Permission, RbacEngine};

/// Policy engine backed by the RBAC system.
///
/// Evaluates permissions for agent actions: messaging, file transfer,
/// log access, and shadow mode.
pub struct PolicyEngine {
    rbac: Arc<RwLock<RbacEngine>>,
}

impl PolicyEngine {
    pub fn new(rbac: Arc<RwLock<RbacEngine>>) -> Self {
        Self { rbac }
    }

    /// Check if a sender can send a message to a recipient
    pub async fn check_send_message(&self, sender_did: &str, recipient_did: &str) -> bool {
        let rbac = self.rbac.read().await;
        rbac.can_send_to(sender_did, recipient_did)
    }

    /// Check if a sender can transfer a file to a recipient
    pub async fn check_transfer_file(&self, sender_did: &str, recipient_did: &str) -> bool {
        let rbac = self.rbac.read().await;
        rbac.can_transfer_to(sender_did, recipient_did)
    }

    /// Check if a viewer can view a target agent's logs
    pub async fn check_view_logs(&self, viewer_did: &str, target_did: &str) -> bool {
        let rbac = self.rbac.read().await;
        rbac.can_view_logs(viewer_did, target_did)
    }

    /// Check a generic permission for an agent
    pub async fn check_permission(&self, agent_did: &str, permission: &Permission) -> bool {
        let rbac = self.rbac.read().await;
        rbac.has_permission(agent_did, permission)
    }

    /// Check if an agent can enable shadow mode
    pub async fn check_shadow_mode(&self, agent_did: &str) -> bool {
        let rbac = self.rbac.read().await;
        rbac.has_permission(agent_did, &Permission::EnableShadowMode)
    }

    /// Get the role name for an agent
    pub async fn get_agent_role_name(&self, agent_did: &str) -> Option<String> {
        let rbac = self.rbac.read().await;
        rbac.get_agent_role_name(agent_did).cloned()
    }

    /// Get a reference to the underlying RBAC engine
    pub fn rbac(&self) -> &Arc<RwLock<RbacEngine>> {
        &self.rbac
    }
}

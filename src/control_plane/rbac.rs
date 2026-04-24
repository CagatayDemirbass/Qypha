use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Permissions that can be granted to agents via roles
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    SendMessage,
    ReceiveMessage,
    TransferFile,
    ReceiveFile,
    ViewOwnLogs,
    ViewAllLogs,
    ChangePolicy,
    AssignRole,
    EnableShadowMode,
}

impl Permission {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SendMessage" => Some(Self::SendMessage),
            "ReceiveMessage" => Some(Self::ReceiveMessage),
            "TransferFile" => Some(Self::TransferFile),
            "ReceiveFile" => Some(Self::ReceiveFile),
            "ViewOwnLogs" => Some(Self::ViewOwnLogs),
            "ViewAllLogs" => Some(Self::ViewAllLogs),
            "ChangePolicy" => Some(Self::ChangePolicy),
            "AssignRole" => Some(Self::AssignRole),
            "EnableShadowMode" => Some(Self::EnableShadowMode),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SendMessage => "SendMessage",
            Self::ReceiveMessage => "ReceiveMessage",
            Self::TransferFile => "TransferFile",
            Self::ReceiveFile => "ReceiveFile",
            Self::ViewOwnLogs => "ViewOwnLogs",
            Self::ViewAllLogs => "ViewAllLogs",
            Self::ChangePolicy => "ChangePolicy",
            Self::AssignRole => "AssignRole",
            Self::EnableShadowMode => "EnableShadowMode",
        }
    }
}

/// A role definition with permissions and communication restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub name: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
    /// Which roles this role can send messages to (empty = all roles)
    pub can_message_roles: Vec<String>,
    /// Which roles this role can transfer files to (empty = all roles)
    pub can_transfer_to_roles: Vec<String>,
    pub is_template: bool,
}

/// Serializable RBAC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacConfig {
    pub roles: HashMap<String, RoleDefinition>,
    pub assignments: HashMap<String, String>,
}

/// RBAC engine that evaluates permissions at runtime
pub struct RbacEngine {
    config: RbacConfig,
    store_path: PathBuf,
}

impl RbacEngine {
    /// Resolve legacy/wizard role names to canonical RBAC templates.
    fn canonical_role_name(role_name: &str) -> String {
        match role_name {
            "agent" => "agent".to_string(),
            "field" => "finance".to_string(),
            "analyst" => "data_scientist".to_string(),
            "commander" => "executive".to_string(),
            "relay" => "executive".to_string(),
            _ => role_name.to_string(),
        }
    }

    /// Create a new RBAC engine with default role templates
    pub fn new(store_path: &Path) -> Self {
        Self {
            config: RbacConfig {
                roles: Self::default_templates(),
                assignments: HashMap::new(),
            },
            store_path: store_path.to_path_buf(),
        }
    }

    /// Load RBAC configuration from disk
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: RbacConfig = serde_json::from_str(&content)?;
        Ok(Self {
            config,
            store_path: path.to_path_buf(),
        })
    }

    /// Save current RBAC configuration to disk
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.config)?;
        std::fs::write(&self.store_path, json)?;
        Ok(())
    }

    /// Initialize from config file definitions
    pub fn from_config(
        config_roles: &HashMap<String, crate::config::RoleDefinitionConfig>,
        config_assignments: &HashMap<String, String>,
        store_path: &Path,
    ) -> Self {
        let mut roles = Self::default_templates();

        // Merge config-defined roles
        for (name, def) in config_roles {
            let permissions: HashSet<Permission> = def
                .permissions
                .iter()
                .filter_map(|s| Permission::from_str(s))
                .collect();

            roles.insert(
                name.clone(),
                RoleDefinition {
                    name: name.clone(),
                    description: def.description.clone(),
                    permissions,
                    can_message_roles: def.can_message_roles.clone(),
                    can_transfer_to_roles: def.can_transfer_to_roles.clone(),
                    is_template: false,
                },
            );
        }

        let assignments = config_assignments
            .iter()
            .map(|(did, role)| (did.clone(), Self::canonical_role_name(role)))
            .collect();

        Self {
            config: RbacConfig { roles, assignments },
            store_path: store_path.to_path_buf(),
        }
    }

    /// Check if an agent has a specific permission
    pub fn has_permission(&self, agent_did: &str, permission: &Permission) -> bool {
        if let Some(role) = self.get_agent_role(agent_did) {
            role.permissions.contains(permission)
        } else {
            false
        }
    }

    /// Check if sender can send messages to recipient
    pub fn can_send_to(&self, sender_did: &str, recipient_did: &str) -> bool {
        if !self.has_permission(sender_did, &Permission::SendMessage) {
            return false;
        }

        let sender_role = match self.get_agent_role(sender_did) {
            Some(r) => r,
            None => return false,
        };

        // Empty list means can message anyone
        if sender_role.can_message_roles.is_empty() {
            return true;
        }

        // Check if recipient's role is in the allowed list
        if let Some(recipient_role_name) = self.config.assignments.get(recipient_did) {
            sender_role.can_message_roles.contains(recipient_role_name)
        } else {
            // Unknown agents — deny by default
            false
        }
    }

    /// Check if sender can transfer files to recipient
    pub fn can_transfer_to(&self, sender_did: &str, recipient_did: &str) -> bool {
        if !self.has_permission(sender_did, &Permission::TransferFile) {
            return false;
        }

        let sender_role = match self.get_agent_role(sender_did) {
            Some(r) => r,
            None => return false,
        };

        if sender_role.can_transfer_to_roles.is_empty() {
            return true;
        }

        if let Some(recipient_role_name) = self.config.assignments.get(recipient_did) {
            sender_role
                .can_transfer_to_roles
                .contains(recipient_role_name)
        } else {
            false
        }
    }

    /// Check if viewer can view target agent's logs
    pub fn can_view_logs(&self, viewer_did: &str, target_did: &str) -> bool {
        if self.has_permission(viewer_did, &Permission::ViewAllLogs) {
            return true;
        }
        if viewer_did == target_did && self.has_permission(viewer_did, &Permission::ViewOwnLogs) {
            return true;
        }
        false
    }

    /// Assign a role to an agent
    pub fn assign_role(&mut self, agent_did: &str, role_name: &str) -> Result<()> {
        let canonical = Self::canonical_role_name(role_name);
        if !self.config.roles.contains_key(&canonical) {
            return Err(anyhow::anyhow!("Role '{}' does not exist", role_name));
        }
        self.config
            .assignments
            .insert(agent_did.to_string(), canonical);
        Ok(())
    }

    /// Create or update a role definition
    pub fn create_role(&mut self, definition: RoleDefinition) -> Result<()> {
        self.config
            .roles
            .insert(definition.name.clone(), definition);
        Ok(())
    }

    /// Get the role definition for an agent (by DID)
    pub fn get_agent_role(&self, agent_did: &str) -> Option<&RoleDefinition> {
        self.config
            .assignments
            .get(agent_did)
            .and_then(|role_name| self.config.roles.get(role_name))
    }

    /// Get the role name for an agent
    pub fn get_agent_role_name(&self, agent_did: &str) -> Option<&String> {
        self.config.assignments.get(agent_did)
    }

    /// Look up a role by name (not by agent DID)
    pub fn get_role_by_name(&self, role_name: &str) -> Option<&RoleDefinition> {
        self.config.roles.get(role_name)
    }

    /// Get all role definitions
    pub fn all_roles(&self) -> &HashMap<String, RoleDefinition> {
        &self.config.roles
    }

    /// Get all assignments
    pub fn all_assignments(&self) -> &HashMap<String, String> {
        &self.config.assignments
    }

    /// Register an agent by role name (auto-assign during enrollment)
    pub fn register_agent_by_role(&mut self, agent_did: &str, role_name: &str) {
        let canonical = Self::canonical_role_name(role_name);
        if self.config.roles.contains_key(&canonical) {
            self.config
                .assignments
                .insert(agent_did.to_string(), canonical);
        }
    }

    /// Default role templates
    pub fn default_templates() -> HashMap<String, RoleDefinition> {
        let mut roles = HashMap::new();

        roles.insert(
            "agent".to_string(),
            RoleDefinition {
                name: "agent".to_string(),
                description: "Default role (roles disabled)".to_string(),
                permissions: [
                    Permission::SendMessage,
                    Permission::ReceiveMessage,
                    Permission::TransferFile,
                    Permission::ReceiveFile,
                    Permission::ViewOwnLogs,
                ]
                .into_iter()
                .collect(),
                can_message_roles: vec![],     // all
                can_transfer_to_roles: vec![], // all
                is_template: true,
            },
        );

        roles.insert(
            "finance".to_string(),
            RoleDefinition {
                name: "finance".to_string(),
                description: "Finance department agent".to_string(),
                permissions: [
                    Permission::SendMessage,
                    Permission::ReceiveMessage,
                    Permission::TransferFile,
                    Permission::ReceiveFile,
                    Permission::ViewOwnLogs,
                ]
                .into_iter()
                .collect(),
                can_message_roles: vec!["finance".into(), "executive".into()],
                can_transfer_to_roles: vec!["data_scientist".into()],
                is_template: true,
            },
        );

        roles.insert(
            "data_scientist".to_string(),
            RoleDefinition {
                name: "data_scientist".to_string(),
                description: "Data science team agent".to_string(),
                permissions: [
                    Permission::SendMessage,
                    Permission::ReceiveMessage,
                    Permission::TransferFile,
                    Permission::ReceiveFile,
                    Permission::ViewOwnLogs,
                ]
                .into_iter()
                .collect(),
                can_message_roles: vec!["data_scientist".into(), "finance".into()],
                can_transfer_to_roles: vec!["data_scientist".into()],
                is_template: true,
            },
        );

        roles.insert(
            "executive".to_string(),
            RoleDefinition {
                name: "executive".to_string(),
                description: "Executive with shadow mode access".to_string(),
                permissions: [
                    Permission::SendMessage,
                    Permission::ReceiveMessage,
                    Permission::TransferFile,
                    Permission::ReceiveFile,
                    Permission::ViewAllLogs,
                    Permission::EnableShadowMode,
                    Permission::ChangePolicy,
                ]
                .into_iter()
                .collect(),
                can_message_roles: vec![],     // all
                can_transfer_to_roles: vec![], // all
                is_template: true,
            },
        );

        roles
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup_engine() -> RbacEngine {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rbac.json");
        let mut engine = RbacEngine::new(&path);
        engine.assign_role("did:nxf:finance1", "finance").unwrap();
        engine.assign_role("did:nxf:ds1", "data_scientist").unwrap();
        engine.assign_role("did:nxf:exec1", "executive").unwrap();
        engine
    }

    #[test]
    fn test_finance_limited_permissions() {
        let engine = setup_engine();
        assert!(engine.has_permission("did:nxf:finance1", &Permission::SendMessage));
        assert!(!engine.has_permission("did:nxf:finance1", &Permission::ViewAllLogs));
    }

    #[test]
    fn test_can_send_to_allowed_role() {
        let engine = setup_engine();
        // Finance can message executive
        assert!(engine.can_send_to("did:nxf:finance1", "did:nxf:exec1"));
    }

    #[test]
    fn test_cannot_send_to_disallowed_role() {
        let engine = setup_engine();
        // Finance cannot message data_scientist (not in allowed list)
        assert!(!engine.can_send_to("did:nxf:finance1", "did:nxf:ds1"));
    }

    #[test]
    fn test_executive_can_send_to_anyone() {
        let engine = setup_engine();
        assert!(engine.can_send_to("did:nxf:exec1", "did:nxf:finance1"));
        assert!(engine.can_send_to("did:nxf:exec1", "did:nxf:ds1"));
        assert!(engine.can_send_to("did:nxf:exec1", "did:nxf:exec1"));
    }

    #[test]
    fn test_transfer_restrictions() {
        let engine = setup_engine();
        // Finance can transfer to data_scientist
        assert!(engine.can_transfer_to("did:nxf:finance1", "did:nxf:ds1"));
        // Finance cannot transfer to executive
        assert!(!engine.can_transfer_to("did:nxf:finance1", "did:nxf:exec1"));
    }

    #[test]
    fn test_view_own_logs() {
        let engine = setup_engine();
        assert!(engine.can_view_logs("did:nxf:finance1", "did:nxf:finance1"));
        assert!(!engine.can_view_logs("did:nxf:finance1", "did:nxf:ds1"));
    }

    #[test]
    fn test_executive_view_all_logs() {
        let engine = setup_engine();
        assert!(engine.can_view_logs("did:nxf:exec1", "did:nxf:finance1"));
        assert!(engine.can_view_logs("did:nxf:exec1", "did:nxf:ds1"));
    }

    #[test]
    fn test_unknown_agent_denied() {
        let engine = setup_engine();
        assert!(!engine.has_permission("did:nxf:unknown", &Permission::SendMessage));
        assert!(!engine.can_send_to("did:nxf:unknown", "did:nxf:exec1"));
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rbac.json");
        let mut engine = RbacEngine::new(&path);
        engine.assign_role("did:nxf:test", "finance").unwrap();
        engine.save().unwrap();

        let loaded = RbacEngine::load(&path).unwrap();
        assert!(loaded.has_permission("did:nxf:test", &Permission::SendMessage));
    }

    #[test]
    fn test_invalid_role_assignment() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rbac.json");
        let mut engine = RbacEngine::new(&path);
        let result = engine.assign_role("did:nxf:test", "nonexistent_role");
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_role_alias_assignment() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rbac.json");
        let mut engine = RbacEngine::new(&path);

        engine.assign_role("did:nxf:field1", "field").unwrap();
        assert!(engine.has_permission("did:nxf:field1", &Permission::SendMessage));
        assert_eq!(
            engine
                .get_agent_role_name("did:nxf:field1")
                .map(|s| s.as_str()),
            Some("finance")
        );

        engine.assign_role("did:nxf:analyst1", "analyst").unwrap();
        assert_eq!(
            engine
                .get_agent_role_name("did:nxf:analyst1")
                .map(|s| s.as_str()),
            Some("data_scientist")
        );
    }

    #[test]
    fn test_permission_from_str() {
        assert_eq!(
            Permission::from_str("SendMessage"),
            Some(Permission::SendMessage)
        );
        assert_eq!(Permission::from_str("invalid"), None);
    }
}

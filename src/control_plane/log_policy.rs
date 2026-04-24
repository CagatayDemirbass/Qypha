use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Log policy mode for an agent
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogPolicy {
    #[serde(alias = "safe", alias = "Safe")]
    Safe,
    /// Ghost: absolute zero trace, immutable.
    #[serde(alias = "ghost", alias = "Ghost")]
    Ghost,
}

impl LogPolicy {
    pub fn try_from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "safe" => Some(Self::Safe),
            "ghost" => Some(Self::Ghost),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Ghost => "ghost",
        }
    }

    /// Returns true if this mode is immutable (cannot be changed remotely)
    pub fn is_immutable(&self) -> bool {
        matches!(self, Self::Ghost)
    }
}

/// Per-agent log policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLogPolicy {
    pub agent_did: String,
    pub mode: LogPolicy,
}

/// Runtime log policy manager
pub struct LogPolicyManager {
    policies: HashMap<String, AgentLogPolicy>,
    store_path: PathBuf,
}

impl LogPolicyManager {
    /// Create a new LogPolicyManager
    pub fn new(store_path: &Path) -> Self {
        Self {
            policies: HashMap::new(),
            store_path: store_path.to_path_buf(),
        }
    }

    /// Load policies from disk
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let policies: HashMap<String, AgentLogPolicy> = serde_json::from_str(&content)?;
        Ok(Self {
            policies,
            store_path: path.to_path_buf(),
        })
    }

    /// Save policies to disk
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.policies)?;
        std::fs::write(&self.store_path, json)?;
        Ok(())
    }

    /// Get the current policy for an agent
    pub fn get_policy(&self, agent_did: &str) -> Option<&AgentLogPolicy> {
        self.policies.get(agent_did)
    }

    /// Get the effective log mode for an agent
    pub fn get_mode(&self, agent_did: &str) -> LogPolicy {
        self.policies
            .get(agent_did)
            .map(|p| p.mode.clone())
            .unwrap_or(LogPolicy::Safe)
    }

    /// Set a policy directly.
    pub fn set_policy(&mut self, policy: AgentLogPolicy) {
        self.policies.insert(policy.agent_did.clone(), policy);
    }

    /// Get all policies
    pub fn all_policies(&self) -> &HashMap<String, AgentLogPolicy> {
        &self.policies
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_set_and_get_policy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log_policies.json");
        let mut mgr = LogPolicyManager::new(&path);

        mgr.set_policy(AgentLogPolicy {
            agent_did: "did:nxf:test".to_string(),
            mode: LogPolicy::Ghost,
        });

        let policy = mgr.get_policy("did:nxf:test").unwrap();
        assert_eq!(policy.mode, LogPolicy::Ghost);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log_policies.json");
        let mut mgr = LogPolicyManager::new(&path);

        mgr.set_policy(AgentLogPolicy {
            agent_did: "did:nxf:test".to_string(),
            mode: LogPolicy::Ghost,
        });
        mgr.save().unwrap();

        let loaded = LogPolicyManager::load(&path).unwrap();
        assert_eq!(loaded.get_mode("did:nxf:test"), LogPolicy::Ghost);
    }

    #[test]
    fn test_default_mode_is_safe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log_policies.json");
        let mgr = LogPolicyManager::new(&path);
        assert_eq!(mgr.get_mode("did:nxf:unknown"), LogPolicy::Safe);
    }

    #[test]
    fn test_log_policy_from_str() {
        assert_eq!(LogPolicy::try_from_str("legacy"), None);
        assert_eq!(LogPolicy::try_from_str("safe"), Some(LogPolicy::Safe));
        assert_eq!(LogPolicy::try_from_str("ghost"), Some(LogPolicy::Ghost));
        assert_eq!(LogPolicy::try_from_str("unknown"), None);
    }
}

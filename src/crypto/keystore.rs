use crate::os_adapter::home::preferred_user_home_dir;
use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Manages agent key storage on disk (encrypted)
/// Future: integrate with OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service)
pub struct KeyStore {
    base_dir: PathBuf,
}

impl KeyStore {
    pub fn sanitize_agent_name(agent_name: &str) -> String {
        agent_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .to_lowercase()
    }

    pub fn new(base_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
        }
    }

    /// Get the default keystore directory: ~/.qypha/keys/
    /// (Legacy — use agent_dir() for multi-agent setups)
    pub fn default_dir() -> Result<PathBuf> {
        let home = dirs_next().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let dir = home.join(".qypha").join("keys");
        std::fs::create_dir_all(&dir)?;
        harden_private_dir(&dir)?;
        Ok(dir)
    }

    /// Per-agent data root: ~/.qypha/agents/<agent_name>/
    ///
    /// Structure:
    ///   ~/.qypha/agents/<name>/
    ///     keys/agent_identity.json
    ///     keys/public_identity.json
    ///     audit/
    ///     rbac.json
    ///     log_policies.json
    pub fn agent_data_path(agent_name: &str) -> Result<PathBuf> {
        let home = dirs_next().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let safe_name = Self::sanitize_agent_name(agent_name);
        Ok(home.join(".qypha").join("agents").join(safe_name))
    }

    pub fn agent_data_dir(agent_name: &str) -> Result<PathBuf> {
        let dir = Self::agent_data_path(agent_name)?;
        std::fs::create_dir_all(&dir)?;
        harden_private_dir(&dir)?;
        Ok(dir)
    }

    /// Keys directory for a specific agent: ~/.qypha/agents/<name>/keys/
    pub fn agent_keys_dir(agent_name: &str) -> Result<PathBuf> {
        let dir = Self::agent_data_dir(agent_name)?.join("keys");
        std::fs::create_dir_all(&dir)?;
        harden_private_dir(&dir)?;
        Ok(dir)
    }

    /// Tor data directory for a specific agent: ~/.qypha/agents/<name>/tor/
    pub fn agent_tor_dir(agent_name: &str) -> Result<PathBuf> {
        let dir = Self::agent_data_dir(agent_name)?.join("tor");
        std::fs::create_dir_all(&dir)?;
        harden_private_dir(&dir)?;
        Ok(dir)
    }

    /// Legacy per-agent config copy path for migration:
    /// ~/.qypha/agents/<name>/config/qypha_<name>.toml
    pub fn agent_config_path(agent_name: &str) -> Result<PathBuf> {
        let dir = Self::agent_data_dir(agent_name)?.join("config");
        std::fs::create_dir_all(&dir)?;
        harden_private_dir(&dir)?;
        Ok(dir.join(format!(
            "qypha_{}.toml",
            Self::sanitize_agent_name(agent_name)
        )))
    }

    pub fn identity_path(&self) -> PathBuf {
        self.base_dir.join("agent_identity.json")
    }

    pub fn peers_dir(&self) -> PathBuf {
        self.base_dir.join("peers")
    }
}

/// List all initialized agent names on this machine
pub fn list_agents() -> Result<Vec<String>> {
    let home = dirs_next().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let agents_dir = home.join(".qypha").join("agents");
    if !agents_dir.exists() {
        return Ok(vec![]);
    }
    let mut agents = Vec::new();
    for entry in std::fs::read_dir(&agents_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let identity = entry.path().join("keys").join("agent_identity.json");
            if identity.exists() {
                if let Some(name) = entry.file_name().to_str() {
                    agents.push(name.to_string());
                }
            }
        }
    }
    agents.sort();
    Ok(agents)
}

/// List all raw per-agent data directories under ~/.qypha/agents, including
/// stale/incomplete roots that may no longer contain an identity file.
pub fn list_agent_data_dirs() -> Result<Vec<PathBuf>> {
    let home = dirs_next().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let agents_dir = home.join(".qypha").join("agents");
    if !agents_dir.exists() {
        return Ok(vec![]);
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&agents_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Cross-platform home directory detection
fn dirs_next() -> Option<PathBuf> {
    preferred_user_home_dir()
}

pub(crate) fn harden_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn harden_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        let parent_missing = !parent.exists();
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create private directory {}", parent.display()))?;
        if parent_missing {
            harden_private_dir(parent)?;
        }
    }

    let tmp_path = private_tmp_path(path);
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "Failed to create temporary private file {}",
                    tmp_path.display()
                )
            })?;
        harden_private_file(&tmp_path)?;
        file.write_all(contents).with_context(|| {
            format!(
                "Failed to write temporary private file {}",
                tmp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "Failed to flush temporary private file {}",
                tmp_path.display()
            )
        })?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    let replace_result = match std::fs::rename(&tmp_path, path) {
        Ok(()) => {
            harden_private_file(path)?;
            sync_parent_dir(path)?;
            Ok(())
        }
        Err(_rename_err) if path.exists() => {
            overwrite_private_file(path, contents)
                .with_context(|| format!("Failed to replace private file {}", path.display()))?;
            let _ = std::fs::remove_file(&tmp_path);
            Ok(())
        }
        Err(rename_err) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(rename_err)
                .with_context(|| format!("Failed to finalize private file {}", path.display()))
        }
    };

    if replace_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    replace_result
}

fn overwrite_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("Failed to open private file {}", path.display()))?;
    harden_private_file(path)?;
    file.write_all(contents)
        .with_context(|| format!("Failed to write private file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to flush private file {}", path.display()))?;
    drop(file);
    harden_private_file(path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn private_tmp_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private");
    parent.join(format!(
        ".{}.{}.tmp",
        file_name,
        uuid::Uuid::new_v4().simple()
    ))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            let dir = match std::fs::File::open(parent) {
                Ok(dir) => dir,
                Err(error) if ignore_directory_sync_error(&error) => return Ok(()),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "Failed to open private parent directory {}",
                            parent.display()
                        )
                    })
                }
            };
            match dir.sync_all() {
                Ok(()) => {}
                Err(error) if ignore_directory_sync_error(&error) => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "Failed to flush private parent directory {}",
                            parent.display()
                        )
                    })
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(unix)]
fn ignore_directory_sync_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
    )
}

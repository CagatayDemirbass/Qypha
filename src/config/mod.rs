use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub mod encrypted_config;
use crate::os_adapter::secure_wipe::secure_wipe_file;
use encrypted_config::{ConfigFieldCipher, EncryptedConfigLoader};

const CONFIG_PASSPHRASE_ENV_VARS: [&str; 3] = [
    "QYPHA_CONFIG_PASSPHRASE",
    "QYPHA_PASSPHRASE",
    "QYPHA_INIT_PASSPHRASE",
];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub agent: AgentConfig,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub roles: RolesConfig,
    #[serde(default)]
    pub transfer: TransferConfig,
}

/// Transport mode for P2P connectivity
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// TCP only — LAN/direct connections (existing behavior)
    Tcp,
    /// Tor only — all traffic routed through Tor onion services
    Tor,
    /// Internet mode over iroh QUIC — direct P2P preferred, relay optional
    Internet,
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Tcp
    }
}

/// Tor-specific configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TorConfig {
    /// Directory for Tor state (consensus cache, keys, etc.)
    /// Default: ~/.qypha/agents/<name>/tor/
    #[serde(default)]
    pub data_dir: Option<String>,

    /// Port the onion service listens on (inside Tor)
    #[serde(default = "TorConfig::default_onion_port")]
    pub onion_port: u16,

    /// Pre-existing onion service private key file path (for persistent .onion address)
    /// If None, a new key is generated and stored in data_dir
    #[serde(default)]
    pub onion_key_file: Option<String>,

    /// Bridge addresses (for censorship circumvention)
    #[serde(default)]
    pub bridges: Vec<String>,

    /// Timeout for Tor circuit establishment (seconds)
    #[serde(default = "TorConfig::default_circuit_timeout")]
    pub circuit_timeout_secs: u64,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            onion_port: 9090,
            onion_key_file: None,
            bridges: vec![],
            circuit_timeout_secs: 120,
        }
    }
}

impl TorConfig {
    fn default_onion_port() -> u16 {
        9090
    }
    fn default_circuit_timeout() -> u64 {
        120
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentConfig {
    pub name: String,
    pub role: String,
    pub did: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub listen_port: u16,
    pub bootstrap_nodes: Vec<String>,
    pub enable_mdns: bool,
    pub enable_kademlia: bool,
    /// Transport mode: tcp, tor, internet (default: tcp for backward compatibility)
    #[serde(default)]
    pub transport_mode: TransportMode,
    /// Tor-specific settings (only used when transport_mode is Tor)
    #[serde(default)]
    pub tor: TorConfig,
    /// Public address for Internet mode invites (e.g., "1.2.3.4" or "myhost.example.com")
    /// If not set, local IP is auto-detected
    #[serde(default)]
    pub public_address: Option<String>,
    /// Hide IP address from invites, banner, and peer store (Internet mode privacy)
    #[serde(default)]
    pub hide_ip: bool,
    /// iroh-specific settings (used when transport_mode is Internet)
    #[serde(default)]
    pub iroh: IrohConfig,
    /// Shared Tor mailbox service settings for sandbox groups
    #[serde(default)]
    pub mailbox: MailboxConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MailboxConfig {
    /// Tor mailbox service endpoint, e.g. "tor://abcdef...xyz.onion:9444"
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Optional external Tor mailbox relay pool. New groups pick a random relay from this pool.
    #[serde(default)]
    pub pool_endpoints: Vec<String>,
    /// Poll interval for joined group mailboxes
    #[serde(default = "MailboxConfig::default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// Maximum opaque mailbox payload size accepted by the relay
    #[serde(default = "MailboxConfig::default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// Optional dedicated Tor client data dir for mailbox outbound traffic
    #[serde(default)]
    pub client_tor_data_dir: Option<String>,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            pool_endpoints: vec![],
            poll_interval_ms: 5_000,
            max_payload_bytes: 256 * 1024,
            client_tor_data_dir: None,
        }
    }
}

impl MailboxConfig {
    fn default_poll_interval_ms() -> u64 {
        5_000
    }

    fn default_max_payload_bytes() -> usize {
        256 * 1024
    }
}

/// iroh-specific configuration for Internet mode.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IrohConfig {
    /// Enable relay-assisted connectivity (recommended on mixed NAT environments).
    #[serde(default = "IrohConfig::default_relay_enabled")]
    pub relay_enabled: bool,
    /// Enable direct P2P candidate addresses in invites.
    /// When true, peers can upgrade to direct paths for better throughput/latency.
    #[serde(default = "IrohConfig::default_direct_enabled")]
    pub direct_enabled: bool,
    /// Optional custom relay URLs. If empty and relay_enabled=true, iroh defaults are used.
    #[serde(default)]
    pub relay_urls: Vec<String>,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            relay_enabled: true,
            direct_enabled: false,
            relay_urls: vec![],
        }
    }
}

impl IrohConfig {
    fn default_relay_enabled() -> bool {
        true
    }

    fn default_direct_enabled() -> bool {
        false
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityConfig {
    pub require_mtls: bool,
    pub max_message_size_bytes: usize,
    pub nonce_window_size: u64,
    pub shadow_mode_enabled: bool,
    /// Audit log mode: "safe" | "ghost"
    #[serde(default = "SecurityConfig::default_log_mode")]
    pub log_mode: String,
    /// Default TTL for messages in milliseconds (0 = no expiry)
    #[serde(default)]
    pub message_ttl_ms: u64,
    /// Maximum requests per minute per peer (0 = unlimited)
    #[serde(default = "SecurityConfig::default_rate_limit")]
    pub rate_limit_per_minute: u64,
    /// Replay detection window in seconds
    #[serde(default = "SecurityConfig::default_replay_window")]
    pub replay_window_seconds: u64,
    /// Enable certificate pinning for mTLS
    #[serde(default)]
    pub enable_certificate_pinning: bool,
    /// Cover traffic configuration for traffic analysis resistance
    #[serde(default)]
    pub cover_traffic: CoverTrafficConfig,
}

/// Cover traffic configuration — sends random noise packets to prevent timing analysis
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoverTrafficConfig {
    /// When to activate cover traffic: "auto" (Ghost only), "always", "off"
    #[serde(default = "CoverTrafficConfig::default_mode")]
    pub mode: String,
    /// Interval between cover traffic packets in seconds
    #[serde(default = "CoverTrafficConfig::default_interval")]
    pub interval_secs: u64,
    /// Size of each cover traffic packet in bytes
    #[serde(default = "CoverTrafficConfig::default_packet_size")]
    pub packet_size: usize,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            mode: "auto".to_string(),
            interval_secs: 30,
            packet_size: 4096,
        }
    }
}

impl CoverTrafficConfig {
    fn default_mode() -> String {
        "auto".to_string()
    }
    fn default_interval() -> u64 {
        30
    }
    fn default_packet_size() -> usize {
        4096
    }
}

/// Logging configuration — controls per-agent log behavior
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoggingConfig {
    /// Default log mode: "safe" | "ghost"
    #[serde(default = "LoggingConfig::default_mode")]
    pub mode: String,
    /// Max entries per log file before rotation
    #[serde(default = "LoggingConfig::default_max_entries")]
    pub max_entries_per_file: u64,
}

/// Roles configuration — flexible RBAC
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RolesConfig {
    /// Path to external roles definition file
    #[serde(default)]
    pub roles_file: Option<String>,
    /// Inline role definitions
    #[serde(default)]
    pub definitions: HashMap<String, RoleDefinitionConfig>,
    /// Agent DID -> role name assignments
    #[serde(default)]
    pub assignments: HashMap<String, String>,
}

/// A role definition in config
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoleDefinitionConfig {
    pub description: String,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub can_message_roles: Vec<String>,
    #[serde(default)]
    pub can_transfer_to_roles: Vec<String>,
}

/// Transfer configuration for chunked file transfer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferConfig {
    /// Chunk size in bytes (default: 4MB)
    #[serde(default = "TransferConfig::default_chunk_size")]
    pub chunk_size_bytes: usize,
    /// Files above this threshold use chunked transfer (default: 10MB)
    #[serde(default = "TransferConfig::default_large_threshold")]
    pub large_file_threshold: usize,
    /// Maximum concurrent chunk uploads
    #[serde(default = "TransferConfig::default_parallel")]
    pub max_parallel_chunks: usize,
    /// Enable session persistence for resumable transfers
    #[serde(default = "TransferConfig::default_resume")]
    pub enable_resume: bool,
    /// Allow temporary disk staging for large transfers in zero-trace modes.
    /// Only content is staged with random file names; resume metadata can stay in-memory.
    #[serde(default = "TransferConfig::default_zero_trace_disk_staging")]
    pub allow_disk_chunk_staging_in_zero_trace: bool,
}

// ─── Defaults ────────────────────────────────────────────────────────────────

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 9090,
            bootstrap_nodes: vec![],
            enable_mdns: true,
            enable_kademlia: true,
            transport_mode: TransportMode::Tcp,
            tor: TorConfig::default(),
            public_address: None,
            // Privacy-first default: do not expose local IP in invites/display.
            hide_ip: true,
            iroh: IrohConfig::default(),
            mailbox: MailboxConfig::default(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_mtls: true,
            max_message_size_bytes: 10 * 1024 * 1024,
            nonce_window_size: 1000,
            shadow_mode_enabled: false,
            log_mode: "safe".to_string(),
            message_ttl_ms: 300_000,
            rate_limit_per_minute: 60,
            replay_window_seconds: 300,
            enable_certificate_pinning: false,
            cover_traffic: CoverTrafficConfig::default(),
        }
    }
}

impl SecurityConfig {
    fn default_log_mode() -> String {
        "safe".to_string()
    }
    fn default_rate_limit() -> u64 {
        60
    }
    fn default_replay_window() -> u64 {
        300
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            mode: "safe".to_string(),
            max_entries_per_file: 10_000,
        }
    }
}

impl LoggingConfig {
    fn default_mode() -> String {
        "safe".to_string()
    }
    fn default_max_entries() -> u64 {
        10_000
    }
}

impl Default for RolesConfig {
    fn default() -> Self {
        Self {
            roles_file: None,
            definitions: HashMap::new(),
            assignments: HashMap::new(),
        }
    }
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            chunk_size_bytes: 4 * 1024 * 1024,
            large_file_threshold: 10 * 1024 * 1024,
            max_parallel_chunks: 4,
            enable_resume: true,
            allow_disk_chunk_staging_in_zero_trace: false,
        }
    }
}

impl TransferConfig {
    fn default_chunk_size() -> usize {
        4 * 1024 * 1024
    }
    fn default_large_threshold() -> usize {
        10 * 1024 * 1024
    }
    fn default_parallel() -> usize {
        4
    }
    fn default_resume() -> bool {
        true
    }
    fn default_zero_trace_disk_staging() -> bool {
        false
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        if has_unsupported_transport_mode(&content)? {
            secure_wipe_file(Path::new(path));
            anyhow::bail!(
                "Config '{}' uses an unsupported transport mode and was securely deleted.",
                path
            );
        }
        let config: Self = toml::from_str(&content)?;
        if config.has_unsupported_log_mode() {
            secure_wipe_file(Path::new(path));
            anyhow::bail!(
                "Config '{}' uses an unsupported log mode and was securely deleted.",
                path
            );
        }
        Ok(config)
    }

    pub fn has_unsupported_log_mode(&self) -> bool {
        unsupported_log_mode_value(&self.security.log_mode)
            || unsupported_log_mode_value(&self.logging.mode)
    }

    pub fn to_toml_string_pretty_with_sensitive_encryption(
        &self,
        passphrase: Option<&str>,
    ) -> Result<String> {
        let mut config = self.clone();
        config.encrypt_sensitive_fields(passphrase)?;
        Ok(toml::to_string_pretty(&config)?)
    }

    pub fn has_encrypted_sensitive_fields(&self) -> bool {
        option_str_is_encrypted(&self.network.public_address)
            || vec_has_encrypted_values(&self.network.bootstrap_nodes)
            || option_str_is_encrypted(&self.network.tor.data_dir)
            || option_str_is_encrypted(&self.network.tor.onion_key_file)
            || vec_has_encrypted_values(&self.network.tor.bridges)
            || vec_has_encrypted_values(&self.network.iroh.relay_urls)
            || option_str_is_encrypted(&self.network.mailbox.endpoint)
            || vec_has_encrypted_values(&self.network.mailbox.pool_endpoints)
            || option_str_is_encrypted(&self.network.mailbox.client_tor_data_dir)
            || option_str_is_encrypted(&self.roles.roles_file)
    }

    pub fn decrypt_sensitive_fields(&mut self, passphrase: Option<&str>) -> Result<()> {
        let mut decrypt_cache = HashMap::new();
        decrypt_vec_field(
            passphrase,
            &mut decrypt_cache,
            "network.bootstrap_nodes",
            &mut self.network.bootstrap_nodes,
        )?;
        decrypt_option_field(
            passphrase,
            &mut decrypt_cache,
            "network.public_address",
            &mut self.network.public_address,
        )?;
        decrypt_option_field(
            passphrase,
            &mut decrypt_cache,
            "network.tor.data_dir",
            &mut self.network.tor.data_dir,
        )?;
        decrypt_option_field(
            passphrase,
            &mut decrypt_cache,
            "network.tor.onion_key_file",
            &mut self.network.tor.onion_key_file,
        )?;
        decrypt_vec_field(
            passphrase,
            &mut decrypt_cache,
            "network.tor.bridges",
            &mut self.network.tor.bridges,
        )?;
        decrypt_vec_field(
            passphrase,
            &mut decrypt_cache,
            "network.iroh.relay_urls",
            &mut self.network.iroh.relay_urls,
        )?;
        decrypt_option_field(
            passphrase,
            &mut decrypt_cache,
            "network.mailbox.endpoint",
            &mut self.network.mailbox.endpoint,
        )?;
        decrypt_vec_field(
            passphrase,
            &mut decrypt_cache,
            "network.mailbox.pool_endpoints",
            &mut self.network.mailbox.pool_endpoints,
        )?;
        decrypt_option_field(
            passphrase,
            &mut decrypt_cache,
            "network.mailbox.client_tor_data_dir",
            &mut self.network.mailbox.client_tor_data_dir,
        )?;
        decrypt_option_field(
            passphrase,
            &mut decrypt_cache,
            "roles.roles_file",
            &mut self.roles.roles_file,
        )?;
        Ok(())
    }

    fn encrypt_sensitive_fields(&mut self, passphrase: Option<&str>) -> Result<()> {
        let encryptor = passphrase
            .map(EncryptedConfigLoader::batch_encryptor)
            .transpose()?;
        encrypt_vec_field(
            encryptor.as_ref(),
            "network.bootstrap_nodes",
            &mut self.network.bootstrap_nodes,
        )?;
        encrypt_option_field(
            encryptor.as_ref(),
            "network.public_address",
            &mut self.network.public_address,
        )?;
        encrypt_option_field(
            encryptor.as_ref(),
            "network.tor.data_dir",
            &mut self.network.tor.data_dir,
        )?;
        encrypt_option_field(
            encryptor.as_ref(),
            "network.tor.onion_key_file",
            &mut self.network.tor.onion_key_file,
        )?;
        encrypt_vec_field(
            encryptor.as_ref(),
            "network.tor.bridges",
            &mut self.network.tor.bridges,
        )?;
        encrypt_vec_field(
            encryptor.as_ref(),
            "network.iroh.relay_urls",
            &mut self.network.iroh.relay_urls,
        )?;
        encrypt_option_field(
            encryptor.as_ref(),
            "network.mailbox.endpoint",
            &mut self.network.mailbox.endpoint,
        )?;
        encrypt_vec_field(
            encryptor.as_ref(),
            "network.mailbox.pool_endpoints",
            &mut self.network.mailbox.pool_endpoints,
        )?;
        encrypt_option_field(
            encryptor.as_ref(),
            "network.mailbox.client_tor_data_dir",
            &mut self.network.mailbox.client_tor_data_dir,
        )?;
        encrypt_option_field(
            encryptor.as_ref(),
            "roles.roles_file",
            &mut self.roles.roles_file,
        )?;
        Ok(())
    }
}

pub fn config_passphrase_from_env() -> Option<String> {
    CONFIG_PASSPHRASE_ENV_VARS.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn option_str_is_encrypted(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(EncryptedConfigLoader::is_encrypted)
}

fn vec_has_encrypted_values(values: &[String]) -> bool {
    values
        .iter()
        .any(|value| EncryptedConfigLoader::is_encrypted(value))
}

fn encrypt_option_field(
    encryptor: Option<&ConfigFieldCipher>,
    field: &str,
    value: &mut Option<String>,
) -> Result<()> {
    let Some(current) = value.as_mut() else {
        return Ok(());
    };
    let trimmed = current.trim();
    if trimmed.is_empty() || EncryptedConfigLoader::is_encrypted(trimmed) {
        return Ok(());
    }
    let Some(encryptor) = encryptor else {
        return Ok(());
    };
    *current = encryptor
        .encrypt_value(trimmed)
        .map_err(|error| anyhow::anyhow!("Failed to encrypt {}: {}", field, error))?;
    Ok(())
}

fn encrypt_vec_field(
    encryptor: Option<&ConfigFieldCipher>,
    field: &str,
    values: &mut Vec<String>,
) -> Result<()> {
    let Some(encryptor) = encryptor else {
        return Ok(());
    };
    for value in values.iter_mut() {
        let trimmed = value.trim();
        if trimmed.is_empty() || EncryptedConfigLoader::is_encrypted(trimmed) {
            continue;
        }
        *value = encryptor
            .encrypt_value(trimmed)
            .map_err(|error| anyhow::anyhow!("Failed to encrypt {}: {}", field, error))?;
    }
    Ok(())
}

fn decrypt_option_field(
    passphrase: Option<&str>,
    decrypt_cache: &mut HashMap<String, ConfigFieldCipher>,
    field: &str,
    value: &mut Option<String>,
) -> Result<()> {
    let Some(current) = value.as_mut() else {
        return Ok(());
    };
    if !EncryptedConfigLoader::is_encrypted(current) {
        return Ok(());
    }
    let passphrase = passphrase.ok_or_else(|| {
        anyhow::anyhow!(
            "Config field {} is encrypted but no passphrase is available",
            field
        )
    })?;
    let decryptor = cached_decryptor(passphrase, current, decrypt_cache)
        .map_err(|error| anyhow::anyhow!("Failed to prepare decryptor for {}: {}", field, error))?;
    *current = decryptor
        .decrypt_value(current)
        .map_err(|error| anyhow::anyhow!("Failed to decrypt {}: {}", field, error))?;
    Ok(())
}

fn decrypt_vec_field(
    passphrase: Option<&str>,
    decrypt_cache: &mut HashMap<String, ConfigFieldCipher>,
    field: &str,
    values: &mut Vec<String>,
) -> Result<()> {
    for value in values.iter_mut() {
        if !EncryptedConfigLoader::is_encrypted(value) {
            continue;
        }
        let passphrase = passphrase.ok_or_else(|| {
            anyhow::anyhow!(
                "Config field {} is encrypted but no passphrase is available",
                field
            )
        })?;
        let decryptor = cached_decryptor(passphrase, value, decrypt_cache).map_err(|error| {
            anyhow::anyhow!("Failed to prepare decryptor for {}: {}", field, error)
        })?;
        *value = decryptor
            .decrypt_value(value)
            .map_err(|error| anyhow::anyhow!("Failed to decrypt {}: {}", field, error))?;
    }
    Ok(())
}

fn cached_decryptor<'a>(
    passphrase: &str,
    encrypted_value: &str,
    decrypt_cache: &'a mut HashMap<String, ConfigFieldCipher>,
) -> Result<&'a ConfigFieldCipher> {
    let cache_key = EncryptedConfigLoader::cache_key_for_encrypted_value(encrypted_value)?;
    if !decrypt_cache.contains_key(&cache_key) {
        let decryptor =
            EncryptedConfigLoader::decryptor_for_encrypted_value(passphrase, encrypted_value)?;
        decrypt_cache.insert(cache_key.clone(), decryptor);
    }
    Ok(decrypt_cache
        .get(&cache_key)
        .expect("decrypt cache entry inserted before lookup"))
}

fn unsupported_log_mode_value(mode: &str) -> bool {
    let trimmed = mode.trim();
    !trimmed.is_empty() && !matches!(trimmed.to_ascii_lowercase().as_str(), "safe" | "ghost")
}

fn has_unsupported_transport_mode(content: &str) -> Result<bool> {
    let parsed = toml::from_str::<toml::Value>(content)?;
    let transport_mode = parsed
        .get("network")
        .and_then(|network| network.get("transport_mode"))
        .and_then(toml::Value::as_str)
        .unwrap_or("");
    Ok(unsupported_transport_mode_value(transport_mode))
}

fn unsupported_transport_mode_value(mode: &str) -> bool {
    let trimmed = mode.trim();
    !trimmed.is_empty()
        && !matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "tcp" | "tor" | "internet"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn sensitive_fields_roundtrip_through_encrypted_toml() {
        let mut config = AppConfig {
            agent: AgentConfig {
                name: "alice".to_string(),
                role: "agent".to_string(),
                did: "did:nxf:alice".to_string(),
            },
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            roles: RolesConfig::default(),
            transfer: TransferConfig::default(),
        };
        config.network.public_address = Some("198.51.100.10".to_string());
        config.network.bootstrap_nodes = vec!["/ip4/203.0.113.9/tcp/4001".to_string()];
        config.network.mailbox.pool_endpoints = vec![
            "tor://relay-a.example.onion:9444".to_string(),
            "tor://relay-b.example.onion:9444".to_string(),
        ];
        config.network.iroh.relay_urls = vec!["https://relay.example.test".to_string()];
        config.roles.roles_file = Some("/opt/qypha/roles.toml".to_string());

        let toml = config
            .to_toml_string_pretty_with_sensitive_encryption(Some("correct horse battery staple"))
            .unwrap();
        assert!(!toml.contains("198.51.100.10"));
        assert!(!toml.contains("relay-a.example.onion"));
        assert!(!toml.contains("/opt/qypha/roles.toml"));

        let mut parsed: AppConfig = toml::from_str(&toml).unwrap();
        assert!(parsed.has_encrypted_sensitive_fields());
        parsed
            .decrypt_sensitive_fields(Some("correct horse battery staple"))
            .unwrap();

        assert_eq!(
            parsed.network.public_address.as_deref(),
            Some("198.51.100.10")
        );
        assert_eq!(parsed.network.bootstrap_nodes.len(), 1);
        assert_eq!(parsed.network.mailbox.pool_endpoints.len(), 2);
        assert_eq!(
            parsed.roles.roles_file.as_deref(),
            Some("/opt/qypha/roles.toml")
        );
    }

    #[test]
    fn decrypt_sensitive_fields_requires_passphrase_when_enc_present() {
        let mut config = AppConfig {
            agent: AgentConfig {
                name: "alice".to_string(),
                role: "agent".to_string(),
                did: "did:nxf:alice".to_string(),
            },
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            roles: RolesConfig::default(),
            transfer: TransferConfig::default(),
        };
        config.network.mailbox.endpoint = Some(
            EncryptedConfigLoader::encrypt_value("pass", "tor://relay.example.onion:9444").unwrap(),
        );

        let error = config.decrypt_sensitive_fields(None).unwrap_err();
        assert!(error.to_string().contains("no passphrase is available"));
    }

    #[test]
    fn decrypt_sensitive_fields_handles_multiple_field_salts() {
        let passphrase = "correct horse battery staple";
        let mut config = AppConfig {
            agent: AgentConfig {
                name: "alice".to_string(),
                role: "agent".to_string(),
                did: "did:nxf:alice".to_string(),
            },
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            roles: RolesConfig::default(),
            transfer: TransferConfig::default(),
        };
        config.network.public_address =
            Some(EncryptedConfigLoader::encrypt_value(passphrase, "198.51.100.10").unwrap());
        config.network.mailbox.endpoint = Some(
            EncryptedConfigLoader::encrypt_value(passphrase, "tor://relay.example.onion:9444")
                .unwrap(),
        );

        config.decrypt_sensitive_fields(Some(passphrase)).unwrap();
        assert_eq!(
            config.network.public_address.as_deref(),
            Some("198.51.100.10")
        );
        assert_eq!(
            config.network.mailbox.endpoint.as_deref(),
            Some("tor://relay.example.onion:9444")
        );
    }

    #[test]
    fn load_rejects_and_wipes_unsupported_log_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.toml");
        let mut config = AppConfig {
            agent: AgentConfig {
                name: "alice".to_string(),
                role: "agent".to_string(),
                did: "did:nxf:alice".to_string(),
            },
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            roles: RolesConfig::default(),
            transfer: TransferConfig::default(),
        };
        config.security.log_mode = "legacy".to_string();
        config.logging.mode = "legacy".to_string();
        fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let error = AppConfig::load(path.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("unsupported log mode"));
        assert!(!path.exists());
    }
}

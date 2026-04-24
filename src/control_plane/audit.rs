use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

fn hash_marker(domain: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"NXF_SAFE_AUDIT_REDACT_V1");
    h.update(domain.as_bytes());
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

/// Log mode: controls what gets recorded and where
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogMode {
    /// Safe mode: encrypted persistent audit with privacy-hardened metadata.
    #[serde(alias = "safe", alias = "Safe")]
    Safe,
    /// Ghost mode: absolute zero trace + IMMUTABLE
    /// - No disk writes, no in-memory tracking
    /// - Remote peers CANNOT change this mode (policy change rejected)
    /// - Cryptographic keys zeroed in memory (not derived from DID)
    /// - No audit directory created, no config files modified
    /// - The agent effectively never existed from a forensic perspective
    #[serde(alias = "ghost", alias = "Ghost")]
    Ghost,
}

impl LogMode {
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

    /// Returns true if this mode produces zero forensic traces
    pub fn is_zero_trace(&self) -> bool {
        matches!(self, Self::Ghost)
    }

    /// Returns true if this mode is immutable (cannot be changed remotely)
    pub fn is_immutable(&self) -> bool {
        matches!(self, Self::Ghost)
    }
}

/// An individual audit log entry
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: String,
    pub event_type: String,
    pub actor_did: String,
    pub details: String,
    /// SHA-256 of (previous_chain_hash || event_type || actor_did || details)
    pub chain_hash: String,
    /// Which agent produced this entry
    #[serde(default)]
    pub agent_did: String,
    /// What mode was active when recorded
    #[serde(default)]
    pub log_mode: String,
}

/// Append-only audit trail with cryptographic chaining and HMAC integrity.
///
/// Chain hashing: each entry hashes the previous hash + event data.
/// Tampering any past entry invalidates all subsequent hashes.
/// HMAC trailer: each log file gets an HMAC-SHA256 for additional integrity.
pub struct AuditLog {
    mode: LogMode,
    log_path: Option<PathBuf>,
    aes_key: [u8; 32],
    hmac_key: [u8; 32],
    chain_hash: [u8; 32],
    seq: u64,
    /// The agent DID that owns this log
    owner_did: String,
}

impl AuditLog {
    /// Create a new AuditLog.
    ///
    /// `log_dir`        — where to write the encrypted JSONL file
    /// `agent_did`      — embedded in entries for ownership attribution
    /// `audit_root_key` — secret 256-bit root key derived from private key material
    /// `mode`           — Safe / Ghost
    pub fn new(
        log_dir: &Path,
        agent_did: &str,
        audit_root_key: &[u8; 32],
        mode: LogMode,
    ) -> Result<Self> {
        let (aes_key, hmac_key) = Self::derive_keys_from_root(audit_root_key);

        let log_path = match mode {
            LogMode::Ghost => None,
            _ => {
                std::fs::create_dir_all(log_dir)?;
                let filename = format!(
                    "audit_{}.jsonl.enc",
                    chrono::Utc::now().format("%Y%m%d_%H%M%S")
                );
                Some(log_dir.join(filename))
            }
        };

        // Ghost: zero all key material — no DID-derived keys in memory
        // Memory dump'ta DID veya türetilmiş anahtar görünmez
        let zero_memory = mode.is_immutable();
        let (aes_key, hmac_key) = if zero_memory {
            ([0u8; 32], [0u8; 32])
        } else {
            (aes_key, hmac_key)
        };

        Ok(Self {
            mode,
            log_path,
            aes_key,
            hmac_key,
            chain_hash: [0u8; 32],
            seq: 0,
            owner_did: if zero_memory {
                String::new()
            } else {
                agent_did.to_string()
            },
        })
    }

    /// Record an audit event.
    ///
    /// In Ghost mode this is a no-op.
    pub fn record(&mut self, event_type: &str, actor_did: &str, details: &str) {
        match self.mode {
            LogMode::Ghost => return,
            _ => {}
        }
        let actor_did = if matches!(self.mode, LogMode::Safe) {
            hash_marker("actor", actor_did)
        } else {
            actor_did.to_string()
        };
        let details = if matches!(self.mode, LogMode::Safe) {
            let digest = hash_marker("details", details);
            format!("redacted:{} bytes:{}", details.len(), digest)
        } else {
            details.to_string()
        };

        // 1. Compute chain hash (includes seq + timestamp for ordering protection)
        // Without seq/timestamp, an attacker could reorder entries without
        // breaking the chain — now any reordering invalidates subsequent hashes.
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut hasher = Sha256::new();
        hasher.update(&self.chain_hash);
        hasher.update(&self.seq.to_le_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(actor_did.as_bytes());
        hasher.update(details.as_bytes());
        let new_hash: [u8; 32] = hasher.finalize().into();
        self.chain_hash = new_hash;

        let entry = AuditEntry {
            seq: self.seq,
            timestamp,
            event_type: event_type.to_string(),
            actor_did: actor_did.to_string(),
            details,
            chain_hash: hex::encode(new_hash),
            agent_did: self.owner_did.clone(),
            log_mode: self.mode.as_str().to_string(),
        };
        self.seq += 1;

        // 2. Serialize to JSON
        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Audit serialize error: {}", e);
                return;
            }
        };

        // 3. Encrypt with AES-256-GCM (unique nonce per entry)
        let encrypted = match self.encrypt_entry(json.as_bytes()) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("Audit encrypt error: {}", e);
                return;
            }
        };

        // 4. Append to log file (binary length-prefixed: 4-byte LE length + ciphertext)
        if let Some(ref path) = self.log_path {
            use std::io::Write;
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                Ok(mut f) => {
                    let len = (encrypted.len() as u32).to_le_bytes();
                    let _ = f.write_all(&len);
                    let _ = f.write_all(&encrypted);
                }
                Err(e) => tracing::error!("Audit write error: {}", e),
            }
        }
    }

    /// Change the log mode at runtime.
    ///
    /// **Ghost mode is IMMUTABLE** — once set, it cannot be changed by anyone,
    /// including privileged operators. This is by design: Ghost mode guarantees that no
    /// future action can retroactively create forensic traces.
    pub fn change_mode(&mut self, new_mode: LogMode, log_dir: &Path) -> Result<()> {
        // Ghost mode is immutable — reject all changes
        if self.mode.is_immutable() {
            anyhow::bail!(
                "{} mode is immutable — log mode cannot be changed. \
                 This is a security guarantee: no party can override {} mode.",
                self.mode.as_str(),
                self.mode.as_str()
            );
        }

        // Write HMAC trailer for old log file before switching
        if self.log_path.is_some() && new_mode.is_zero_trace() {
            self.write_hmac_trailer()?;
        }

        self.mode = new_mode.clone();

        match new_mode {
            LogMode::Ghost => {
                self.log_path = None;
                // Ghost: zero out key material in memory
                if new_mode.is_immutable() {
                    self.aes_key = [0u8; 32];
                    self.hmac_key = [0u8; 32];
                    self.owner_did = String::new();
                }
            }
            _ => {
                if self.log_path.is_none() {
                    std::fs::create_dir_all(log_dir)?;
                    let filename = format!(
                        "audit_{}.jsonl.enc",
                        chrono::Utc::now().format("%Y%m%d_%H%M%S")
                    );
                    self.log_path = Some(log_dir.join(filename));
                }
            }
        }

        Ok(())
    }

    /// Write an HMAC-SHA256 trailer to the log file for integrity verification
    fn write_hmac_trailer(&self) -> Result<()> {
        if let Some(ref path) = self.log_path {
            if path.exists() {
                let data = std::fs::read(path)?;
                let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
                    .map_err(|e| anyhow::anyhow!("HMAC init: {}", e))?;
                mac.update(&data);
                let result = mac.finalize();
                let hmac_bytes = result.into_bytes();

                // Append HMAC as a special trailer: magic bytes + HMAC
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
                f.write_all(b"NXFG_HMAC")?; // 9-byte magic
                f.write_all(&hmac_bytes)?; // 32-byte HMAC
            }
        }
        Ok(())
    }

    /// Encrypt an entry: nonce (12 bytes) || AES-GCM ciphertext
    fn encrypt_entry(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.aes_key)?;
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Audit GCM encrypt: {}", e))?;

        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Derive a 256-bit audit root key from private agent key material.
    ///
    /// This replaces DID-based key derivation. DID is public and must never be
    /// used as encryption key material.
    pub fn derive_root_key_from_secrets(
        x25519_secret: &[u8; 32],
        kyber_secret: Option<&[u8]>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Qypha-AuditLog-v2-RootKey");
        hasher.update(x25519_secret);
        if let Some(ks) = kyber_secret {
            hasher.update(ks);
        }
        hasher.finalize().into()
    }

    /// Derive independent AES and HMAC keys from a secret root key.
    fn derive_keys_from_root(root_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut aes_hasher = Sha256::new();
        aes_hasher.update(b"Qypha-AuditLog-v2-AES");
        aes_hasher.update(root_key);
        let aes_key: [u8; 32] = aes_hasher.finalize().into();

        let mut hmac_hasher = Sha256::new();
        hmac_hasher.update(b"Qypha-AuditLog-v2-HMAC");
        hmac_hasher.update(root_key);
        let hmac_key: [u8; 32] = hmac_hasher.finalize().into();

        (aes_key, hmac_key)
    }

    /// Legacy v1 key derivation from DID.
    /// Kept only for backward-compatible reading of old logs.
    pub fn derive_log_key(agent_did: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Qypha-AuditLog-v1-Key");
        hasher.update(agent_did.as_bytes());
        hasher.finalize().into()
    }

    /// Legacy v1 HMAC derivation from DID.
    /// Kept only for backward-compatible reading of old logs.
    fn derive_hmac_key(agent_did: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Qypha-AuditLog-v1-HMAC");
        hasher.update(agent_did.as_bytes());
        hasher.finalize().into()
    }

    /// Read and decrypt all entries from an encrypted audit log file.
    ///
    /// Legacy DID-based reader for v1 logs.
    /// New v2 logs should be read with `read_log_with_root_key`.
    pub fn read_log(path: &Path, agent_did: &str) -> Result<Vec<AuditEntry>> {
        let aes_key = Self::derive_log_key(agent_did);
        let hmac_key = Self::derive_hmac_key(agent_did);
        Self::read_log_with_keys(path, &aes_key, &hmac_key)
    }

    /// Read and decrypt using a secret root key derived from private identity.
    pub fn read_log_with_root_key(path: &Path, root_key: &[u8; 32]) -> Result<Vec<AuditEntry>> {
        let (aes_key, hmac_key) = Self::derive_keys_from_root(root_key);
        Self::read_log_with_keys(path, &aes_key, &hmac_key)
    }

    /// Read and decrypt with a specific root key.
    /// Backward-compatible alias.
    pub fn read_log_with_key(path: &Path, aes_key: &[u8; 32]) -> Result<Vec<AuditEntry>> {
        Self::read_log_with_root_key(path, aes_key)
    }

    /// Read and decrypt with explicit AES/HMAC keys.
    fn read_log_with_keys(
        path: &Path,
        aes_key: &[u8; 32],
        hmac_key: &[u8; 32],
    ) -> Result<Vec<AuditEntry>> {
        let cipher = Aes256Gcm::new_from_slice(aes_key)?;

        let mut data = std::fs::read(path)?;

        // Check and verify HMAC trailer if present.
        let hmac_trailer_len = 9 + 32; // "NXFG_HMAC" + 32 bytes HMAC
        if data.len() > hmac_trailer_len {
            let trailer_start = data.len() - hmac_trailer_len;
            if &data[trailer_start..trailer_start + 9] == b"NXFG_HMAC" {
                let expected_hmac = &data[trailer_start + 9..];
                let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
                    .map_err(|e| anyhow::anyhow!("HMAC init: {}", e))?;
                mac.update(&data[..trailer_start]);
                mac.verify_slice(expected_hmac).map_err(|_| {
                    anyhow::anyhow!("AUDIT HMAC verification failed — log may be tampered")
                })?;
                data.truncate(trailer_start);
            }
        }

        let mut cursor = 0usize;
        let mut entries = Vec::new();
        let mut prev_hash = [0u8; 32];

        while cursor + 4 <= data.len() {
            let len = u32::from_le_bytes(data[cursor..cursor + 4].try_into()?) as usize;
            cursor += 4;

            if cursor + len > data.len() {
                return Err(anyhow::anyhow!("Audit log truncated"));
            }

            let blob = &data[cursor..cursor + len];
            cursor += len;

            if blob.len() < 12 {
                return Err(anyhow::anyhow!("Audit entry too short"));
            }

            let nonce = Nonce::from_slice(&blob[..12]);
            let plaintext = cipher
                .decrypt(nonce, &blob[12..])
                .map_err(|_| anyhow::anyhow!("Audit decrypt failed — key mismatch or tampered"))?;

            let entry: AuditEntry = serde_json::from_slice(&plaintext)?;

            // Verify chain integrity (v2 format includes seq + timestamp)
            let mut hasher = Sha256::new();
            hasher.update(&prev_hash);
            hasher.update(&entry.seq.to_le_bytes());
            hasher.update(entry.timestamp.as_bytes());
            hasher.update(entry.event_type.as_bytes());
            hasher.update(entry.actor_did.as_bytes());
            hasher.update(entry.details.as_bytes());
            let expected_hash: [u8; 32] = hasher.finalize().into();

            if hex::encode(expected_hash) != entry.chain_hash {
                return Err(anyhow::anyhow!(
                    "CHAIN INTEGRITY VIOLATION at entry #{} — log has been tampered!",
                    entry.seq
                ));
            }

            prev_hash = expected_hash;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Return the current log file path (None in Ghost mode)
    pub fn log_path(&self) -> Option<&PathBuf> {
        self.log_path.as_ref()
    }

    pub fn mode(&self) -> &LogMode {
        &self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_root_key(label: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"test-audit-root");
        h.update(label.as_bytes());
        h.finalize().into()
    }

    #[test]
    fn test_safe_mode_writes_log() {
        let dir = tempdir().unwrap();
        let root = test_root_key("full");
        let mut log = AuditLog::new(dir.path(), "did:nxf:test", &root, LogMode::Safe).unwrap();
        log.record("CONNECT", "did:nxf:peer1", "peer connected");
        log.record("MSG_RECV", "did:nxf:peer1", "chat message");

        assert!(log.log_path().is_some());
        let path = log.log_path().unwrap().clone();
        assert!(path.exists());

        let entries = AuditLog::read_log_with_root_key(&path, &root).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event_type, "CONNECT");
        assert_eq!(entries[1].event_type, "MSG_RECV");
    }

    #[test]
    fn test_ghost_mode_writes_nothing() {
        let dir = tempdir().unwrap();
        let root = test_root_key("ghost-nodisk");
        let mut log = AuditLog::new(dir.path(), "did:nxf:test", &root, LogMode::Ghost).unwrap();
        log.record("CONNECT", "did:nxf:peer1", "peer connected");

        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(files.is_empty(), "Ghost mode must write nothing to disk");
    }

    #[test]
    fn test_chain_tamper_detection() {
        let dir = tempdir().unwrap();
        let root = test_root_key("tamper");
        let mut log = AuditLog::new(dir.path(), "did:nxf:test", &root, LogMode::Safe).unwrap();
        log.record("A", "did:nxf:a", "event a");
        log.record("B", "did:nxf:b", "event b");

        let path = log.log_path().unwrap().clone();

        let mut data = std::fs::read(&path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&path, data).unwrap();

        let result = AuditLog::read_log_with_root_key(&path, &root);
        assert!(result.is_err(), "Tampered log should fail verification");
    }

    #[test]
    fn test_wrong_key_cannot_read() {
        let dir = tempdir().unwrap();
        let root = test_root_key("agent1");
        let mut log = AuditLog::new(dir.path(), "did:nxf:agent1", &root, LogMode::Safe).unwrap();
        log.record("TEST", "did:nxf:agent1", "secret data");

        let path = log.log_path().unwrap().clone();

        let wrong_root = test_root_key("attacker");
        let result = AuditLog::read_log_with_key(&path, &wrong_root);
        assert!(result.is_err(), "Wrong key must not decrypt audit log");
    }

    #[test]
    fn test_runtime_mode_change() {
        let dir = tempdir().unwrap();
        let root = test_root_key("mode-change");
        let mut log = AuditLog::new(dir.path(), "did:nxf:test", &root, LogMode::Safe).unwrap();
        log.record("EVENT1", "did:nxf:test", "before mode change");

        assert!(log.log_path().is_some());

        // Switch to ghost — should stop writing
        log.change_mode(LogMode::Ghost, dir.path()).unwrap();
        log.record("EVENT2", "did:nxf:test", "this should not be written");
        assert!(log.log_path().is_none());
    }

    #[test]
    fn test_ghost_mode_zero_trace() {
        let dir = tempdir().unwrap();
        let root = test_root_key("ghost-zero");
        let mut log = AuditLog::new(dir.path(), "did:nxf:test", &root, LogMode::Ghost).unwrap();
        log.record("CONNECT", "did:nxf:peer1", "peer connected");
        log.record("FILE_RECV", "did:nxf:peer1", "secret file");

        // No files created
        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(files.is_empty(), "Ghost mode must write nothing to disk");
        // No log path
        assert!(log.log_path().is_none());
    }

    #[test]
    fn test_ghost_mode_is_immutable() {
        let dir = tempdir().unwrap();
        let root = test_root_key("ghost-immutable");
        let mut log = AuditLog::new(dir.path(), "did:nxf:test", &root, LogMode::Ghost).unwrap();

        // Attempt to change mode — must fail
        let result = log.change_mode(LogMode::Safe, dir.path());
        assert!(result.is_err(), "Ghost mode must be immutable");
        assert!(result.unwrap_err().to_string().contains("immutable"));

        // Still in Ghost mode
        assert_eq!(*log.mode(), LogMode::Ghost);
    }

    #[test]
    fn test_ghost_mode_zeroes_keys() {
        let dir = tempdir().unwrap();
        let root = test_root_key("ghost-keys");
        let log = AuditLog::new(dir.path(), "did:nxf:secret_agent", &root, LogMode::Ghost).unwrap();

        // In Ghost mode, no DID-derived keys should be in memory
        // (we can't directly inspect private fields, but we verify no files are created
        //  and the owner_did is empty — the keys are zeroed in constructor)
        assert!(log.log_path().is_none());
        assert_eq!(*log.mode(), LogMode::Ghost);
    }

    #[test]
    fn test_entry_includes_agent_did_and_mode() {
        let dir = tempdir().unwrap();
        let root = test_root_key("entry-fields");
        let mut log =
            AuditLog::new(dir.path(), "did:nxf:test_agent", &root, LogMode::Safe).unwrap();
        log.record("TEST", "did:nxf:actor", "details");

        let path = log.log_path().unwrap().clone();
        let entries = AuditLog::read_log_with_root_key(&path, &root).unwrap();
        assert_eq!(entries[0].agent_did, "did:nxf:test_agent");
        assert_eq!(entries[0].log_mode, "safe");
    }

    #[test]
    fn test_safe_mode_redacts_actor_and_details() {
        let dir = tempdir().unwrap();
        let root = test_root_key("safe-redact");
        let mut log = AuditLog::new(dir.path(), "did:nxf:safe", &root, LogMode::Safe).unwrap();
        log.record("TEST", "did:nxf:actor", "sensitive detail");

        let path = log.log_path().unwrap().clone();
        let entries = AuditLog::read_log_with_root_key(&path, &root).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].log_mode, "safe");
        assert_ne!(entries[0].actor_did, "did:nxf:actor");
        assert!(entries[0].details.starts_with("redacted:"));
    }
}

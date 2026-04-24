use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A single entry in the transfer chain — blockchain-like linked hash chain.
///
/// Each entry contains a reference to the previous entry's hash,
/// creating a tamper-evident append-only log of all file transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferChainEntry {
    pub sequence: u64,
    pub artifact_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    pub merkle_root: String,
    pub file_size: u64,
    pub timestamp: u64,
    /// Hash of the previous entry (genesis = "0" * 64)
    pub previous_hash: String,
    /// SHA-256(sequence || artifact_id || sender || recipient || merkle_root || timestamp || previous_hash)
    pub entry_hash: String,
}

impl TransferChainEntry {
    /// Compute the hash for this entry
    fn compute_hash(
        sequence: u64,
        artifact_id: &str,
        sender_did: &str,
        recipient_did: &str,
        merkle_root: &str,
        timestamp: u64,
        previous_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(artifact_id.as_bytes());
        hasher.update(sender_did.as_bytes());
        hasher.update(recipient_did.as_bytes());
        hasher.update(merkle_root.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(previous_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify this entry's hash is correct
    pub fn verify(&self) -> bool {
        let expected = Self::compute_hash(
            self.sequence,
            &self.artifact_id,
            &self.sender_did,
            &self.recipient_did,
            &self.merkle_root,
            self.timestamp,
            &self.previous_hash,
        );
        self.entry_hash == expected
    }
}

/// Append-only transfer chain persisted as JSONL
pub struct TransferChain {
    entries: Vec<TransferChainEntry>,
    latest_hash: String,
    sequence: u64,
    store_path: PathBuf,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl TransferChain {
    /// Create a new empty transfer chain
    pub fn new(store_path: &Path) -> Self {
        Self {
            entries: Vec::new(),
            latest_hash: GENESIS_HASH.to_string(),
            sequence: 0,
            store_path: store_path.to_path_buf(),
        }
    }

    /// Load a transfer chain from disk
    pub fn load(store_path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(store_path)?;
        let mut entries = Vec::new();
        let mut latest_hash = GENESIS_HASH.to_string();
        let mut sequence = 0u64;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: TransferChainEntry = serde_json::from_str(line)?;
            latest_hash = entry.entry_hash.clone();
            sequence = entry.sequence + 1;
            entries.push(entry);
        }

        Ok(Self {
            entries,
            latest_hash,
            sequence,
            store_path: store_path.to_path_buf(),
        })
    }

    /// Append a new transfer to the chain
    pub fn append(
        &mut self,
        artifact_id: &str,
        sender_did: &str,
        recipient_did: &str,
        merkle_root: &str,
        file_size: u64,
    ) -> Result<TransferChainEntry> {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        let entry_hash = TransferChainEntry::compute_hash(
            self.sequence,
            artifact_id,
            sender_did,
            recipient_did,
            merkle_root,
            timestamp,
            &self.latest_hash,
        );

        let entry = TransferChainEntry {
            sequence: self.sequence,
            artifact_id: artifact_id.to_string(),
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
            merkle_root: merkle_root.to_string(),
            file_size,
            timestamp,
            previous_hash: self.latest_hash.clone(),
            entry_hash: entry_hash.clone(),
        };

        // Persist to disk (append JSONL line)
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.store_path)?;
        let json = serde_json::to_string(&entry)?;
        writeln!(file, "{}", json)?;

        self.latest_hash = entry_hash;
        self.sequence += 1;
        self.entries.push(entry.clone());

        Ok(entry)
    }

    /// Verify the integrity of the entire chain
    pub fn verify_integrity(&self) -> Result<bool> {
        let mut prev_hash = GENESIS_HASH.to_string();

        for (i, entry) in self.entries.iter().enumerate() {
            // Check sequence
            if entry.sequence != i as u64 {
                return Err(anyhow::anyhow!(
                    "Sequence gap at index {}: expected {}, got {}",
                    i,
                    i,
                    entry.sequence
                ));
            }

            // Check previous hash linkage
            if entry.previous_hash != prev_hash {
                return Err(anyhow::anyhow!(
                    "Chain break at entry #{}: previous_hash mismatch",
                    i
                ));
            }

            // Verify entry hash
            if !entry.verify() {
                return Err(anyhow::anyhow!(
                    "INTEGRITY VIOLATION at entry #{} — hash mismatch, chain tampered!",
                    i
                ));
            }

            prev_hash = entry.entry_hash.clone();
        }

        Ok(true)
    }

    /// Get the latest hash in the chain
    pub fn latest_hash(&self) -> &str {
        &self.latest_hash
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries
    pub fn entries(&self) -> &[TransferChainEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_append_and_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        let mut chain = TransferChain::new(&path);

        chain
            .append("art_001", "did:nxf:sender", "did:nxf:recv", "aabbcc", 1024)
            .unwrap();
        chain
            .append("art_002", "did:nxf:sender", "did:nxf:recv", "ddeeff", 2048)
            .unwrap();

        assert_eq!(chain.len(), 2);
        assert!(chain.verify_integrity().unwrap());
    }

    #[test]
    fn test_chain_linkage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        let mut chain = TransferChain::new(&path);

        let e1 = chain.append("art_1", "s", "r", "root1", 100).unwrap();
        let e2 = chain.append("art_2", "s", "r", "root2", 200).unwrap();

        assert_eq!(e1.previous_hash, GENESIS_HASH);
        assert_eq!(e2.previous_hash, e1.entry_hash);
    }

    #[test]
    fn test_load_and_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");

        {
            let mut chain = TransferChain::new(&path);
            chain.append("art_1", "s", "r", "root1", 100).unwrap();
            chain.append("art_2", "s", "r", "root2", 200).unwrap();
        }

        let loaded = TransferChain::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");

        {
            let mut chain = TransferChain::new(&path);
            chain.append("art_1", "s", "r", "root1", 100).unwrap();
            chain.append("art_2", "s", "r", "root2", 200).unwrap();
        }

        // Tamper with the file: modify the first entry
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("art_1", "art_X", 1);
        std::fs::write(&path, tampered).unwrap();

        let loaded = TransferChain::load(&path).unwrap();
        let result = loaded.verify_integrity();
        assert!(result.is_err(), "Tampered chain should fail verification");
    }

    #[test]
    fn test_empty_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        let chain = TransferChain::new(&path);
        assert!(chain.is_empty());
        assert!(chain.verify_integrity().unwrap());
    }

    #[test]
    fn test_entry_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        let mut chain = TransferChain::new(&path);
        let entry = chain.append("art_1", "s", "r", "root", 100).unwrap();
        assert!(entry.verify());
    }
}

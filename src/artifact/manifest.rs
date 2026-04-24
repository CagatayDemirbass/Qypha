use serde::{Deserialize, Serialize};

/// Manifest for a local artifact (before/after network transfer)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArtifactManifestLocal {
    pub artifact_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub files: Vec<FileEntryLocal>,
    pub total_size: u64,
    /// Data classification: public | internal | confidential | restricted
    pub classification: String,
    /// SHA-256 of the *plaintext* tar.gz bytes
    pub sha256: String,
    /// Ed25519 signature over SHA-256 hash (hex) — proves sender identity and integrity
    /// Empty for outgoing artifacts before signing; filled in by transfer logic
    #[serde(default)]
    pub sender_signature: Vec<u8>,
    /// Sender's Ed25519 verifying key (hex) — stored for offline verification
    #[serde(default)]
    pub sender_verifying_key_hex: String,
    /// Merkle tree root hash (hex) — for chunked transfer integrity verification
    #[serde(default)]
    pub merkle_root: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntryLocal {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

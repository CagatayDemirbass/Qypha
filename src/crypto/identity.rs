use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::keystore::write_private_file;

pub const DID_METHOD_PREFIX: &str = "did:nxf:";
pub const DID_FINGERPRINT_HEX_LEN: usize = 64;

/// Core agent identity containing cryptographic keypair and metadata.
///
/// Sensitive secret keys are automatically scrubbed from memory on drop
/// via `_signing_key_guard` and `_encryption_secret_guard` fields that
/// implement `Zeroize` on drop (military-grade memory hygiene).
#[derive(Clone)]
pub struct AgentKeyPair {
    // Ed25519: signing / verification
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    // X25519: asymmetric encryption (envelope encryption for file transfer)
    pub encryption_secret: StaticSecret,
    pub encryption_public: X25519PublicKey,
    pub did: String,
    pub metadata: AgentMetadata,
    // ── Post-Quantum Cryptography: Kyber-1024 KEM ────────────────────
    // Hybrid encryption: X25519 (classical) + Kyber-1024 (post-quantum).
    // NIST Level 5 (AES-256 equivalent). Even if quantum computers break
    // X25519, Kyber-1024 protects the session — and vice versa.
    /// Kyber-1024 public key (1568 bytes) for post-quantum hybrid KEM
    pub kyber_public: Vec<u8>,
    /// Kyber-1024 secret key (3168 bytes) for post-quantum hybrid KEM
    pub kyber_secret: Vec<u8>,
    // ── Zeroize-on-drop guards for raw secret bytes ────────────────────
    // These hold a copy of the raw secret bytes and are automatically
    // zeroed when this struct is dropped, ensuring no secret residue
    // remains in memory even if the dalek types don't zero themselves.
    _signing_key_guard: zeroize::Zeroizing<[u8; 32]>,
    _encryption_secret_guard: zeroize::Zeroizing<[u8; 32]>,
    _kyber_secret_guard: zeroize::Zeroizing<Vec<u8>>,
}

/// Manual Drop: overwrite the actual key fields with zeroed keys on drop.
/// Combined with the Zeroizing guards, this provides defense-in-depth.
impl Drop for AgentKeyPair {
    fn drop(&mut self) {
        // Zero the Ed25519 signing key by overwriting with zeroed bytes
        let mut sk_bytes = self.signing_key.to_bytes();
        sk_bytes.zeroize();
        self.signing_key = SigningKey::from_bytes(&sk_bytes);

        // Zero the X25519 secret key by overwriting with zeroed bytes
        let mut x_bytes = self.encryption_secret.to_bytes();
        x_bytes.zeroize();
        self.encryption_secret = StaticSecret::from(x_bytes);

        // Zero the Kyber-1024 secret key
        self.kyber_secret.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AgentMetadata {
    pub display_name: String,
    pub role: String,
    pub enrolled_at: u64,
}

/// Serializable identity (without private key)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentPublicIdentity {
    pub did: String,
    pub public_key_hex: String,
    /// X25519 encryption public key (hex) — shared with peers
    pub encryption_public_key_hex: String,
    pub metadata: AgentMetadata,
    /// Tor v3 onion address (56-char base32, no .onion suffix)
    /// Present only if agent has been started in Tor mode
    #[serde(default)]
    pub onion_address: Option<String>,
    /// Kyber-1024 public key (hex) for post-quantum hybrid encryption
    #[serde(default)]
    pub kyber_public_key_hex: Option<String>,
}

impl AgentKeyPair {
    /// Generate a new agent keypair with a unique DID
    pub fn generate(name: &str, role: &str) -> Self {
        // Ed25519 signing keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // X25519 encryption keypair (independent from signing key)
        let encryption_secret = StaticSecret::random_from_rng(OsRng);
        let encryption_public = X25519PublicKey::from(&encryption_secret);

        // Kyber-1024 post-quantum KEM keypair (NIST Level 5)
        let mut rng = rand::thread_rng();
        let kyber_keys = pqc_kyber::keypair(&mut rng)
            .expect("Kyber-1024 keygen should never fail with a valid RNG");
        let kyber_public = kyber_keys.public.to_vec();
        let kyber_secret = kyber_keys.secret.to_vec();

        // DID is derived only from the Ed25519 public key fingerprint.
        // It never depends on display name, passphrase, device, or location.
        let did = derive_did_from_verifying_key(&verifying_key);

        let metadata = AgentMetadata {
            display_name: name.to_string(),
            role: role.to_string(),
            enrolled_at: chrono::Utc::now().timestamp() as u64,
        };

        tracing::info!(
            did = %did,
            name = %name,
            role = %role,
            "Generated new agent identity (Ed25519 + X25519 + Kyber-1024)"
        );

        let _signing_key_guard = zeroize::Zeroizing::new(signing_key.to_bytes());
        let _encryption_secret_guard = zeroize::Zeroizing::new(encryption_secret.to_bytes());
        let _kyber_secret_guard = zeroize::Zeroizing::new(kyber_secret.clone());

        Self {
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
            did,
            metadata,
            kyber_public,
            kyber_secret,
            _signing_key_guard,
            _encryption_secret_guard,
            _kyber_secret_guard,
        }
    }

    /// Return the X25519 encryption public key bytes
    pub fn x25519_public_key_bytes(&self) -> [u8; 32] {
        *self.encryption_public.as_bytes()
    }

    /// Return the X25519 encryption secret key bytes
    pub fn x25519_secret_key_bytes(&self) -> [u8; 32] {
        self.encryption_secret.to_bytes()
    }

    /// Get public identity (safe to share with peers)
    pub fn public_identity(&self) -> AgentPublicIdentity {
        AgentPublicIdentity {
            did: self.did.clone(),
            public_key_hex: hex::encode(self.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(self.encryption_public.as_bytes()),
            metadata: self.metadata.clone(),
            onion_address: None,
            kyber_public_key_hex: if self.kyber_public.is_empty() {
                None
            } else {
                Some(hex::encode(&self.kyber_public))
            },
        }
    }

    /// Save private keys to encrypted file (Argon2id + AES-256-GCM)
    ///
    /// Military-grade Argon2id parameters: t=4, m=256MB, p=4
    /// This makes brute-force key derivation attacks computationally infeasible
    /// even with dedicated hardware (ASICs, GPUs, FPGAs).
    pub fn save_to_file(&self, path: &Path, passphrase: &str) -> Result<()> {
        use aes_gcm::Nonce;
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

        // Derive encryption key from passphrase with hardened Argon2id parameters
        let salt = rand::random::<[u8; 16]>();
        let argon_config = military_grade_argon2();
        let mut key_bytes = [0u8; 32];
        argon_config
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt Ed25519 signing key
        let encrypted = cipher
            .encrypt(nonce, self.signing_key.as_bytes().as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Encrypt X25519 secret key with a separate nonce
        let nonce_x_bytes = rand::random::<[u8; 12]>();
        let nonce_x = Nonce::from_slice(&nonce_x_bytes);
        let encrypted_x25519 = cipher
            .encrypt(nonce_x, self.encryption_secret.to_bytes().as_ref())
            .map_err(|e| anyhow::anyhow!("X25519 key encryption failed: {}", e))?;

        // Encrypt Kyber-1024 secret key with a separate nonce
        let nonce_k_bytes = rand::random::<[u8; 12]>();
        let nonce_k = Nonce::from_slice(&nonce_k_bytes);
        let encrypted_kyber = cipher
            .encrypt(nonce_k, self.kyber_secret.as_ref())
            .map_err(|e| anyhow::anyhow!("Kyber key encryption failed: {}", e))?;

        let stored = StoredIdentity {
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            encrypted_key: encrypted,
            nonce_x25519: nonce_x_bytes.to_vec(),
            encrypted_x25519,
            nonce_kyber: nonce_k_bytes.to_vec(),
            encrypted_kyber_secret: encrypted_kyber,
            kyber_public_key: self.kyber_public.clone(),
            did: self.did.clone(),
            public_key: self.verifying_key.as_bytes().to_vec(),
            encryption_public_key: self.encryption_public.as_bytes().to_vec(),
            metadata: self.metadata.clone(),
            argon2_version: 2, // Military-grade params
        };

        // Zero the Argon2-derived AES key from memory
        key_bytes.zeroize();

        let json = serde_json::to_string_pretty(&stored)?;
        write_private_file(path, json.as_bytes())?;

        tracing::info!(path = %path.display(), "Agent identity saved (Ed25519 + X25519, encrypted)");
        Ok(())
    }

    /// Load agent identity from encrypted file
    pub fn load_from_file(path: &Path, passphrase: &str) -> Result<Self> {
        use aes_gcm::Nonce;
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

        let json = std::fs::read_to_string(path)?;
        let stored: StoredIdentity = serde_json::from_str(&json)?;

        // Re-derive key from passphrase using the correct Argon2 parameters
        let mut key_bytes = [0u8; 32];
        if stored.argon2_version >= 2 {
            // Military-grade params (v2+)
            let military = military_grade_argon2();
            military
                .hash_password_into(passphrase.as_bytes(), &stored.salt, &mut key_bytes)
                .map_err(|e| anyhow::anyhow!("Key derivation failed (military): {}", e))?;
        } else {
            // Legacy default params (v0/v1) — backward compatibility
            let default_argon = argon2::Argon2::default();
            default_argon
                .hash_password_into(passphrase.as_bytes(), &stored.salt, &mut key_bytes)
                .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
            tracing::warn!(
                "Identity file uses weak Argon2 params. \
                 Re-save with `qypha init` to upgrade to military-grade parameters."
            );
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

        // Zero the Argon2-derived AES key immediately after creating the cipher
        key_bytes.zeroize();

        // Decrypt Ed25519 signing key
        let nonce = Nonce::from_slice(&stored.nonce);
        let mut decrypted = cipher
            .decrypt(nonce, stored.encrypted_key.as_ref())
            .map_err(|_| anyhow::anyhow!("Decryption failed — wrong passphrase?"))?;

        let key_bytes_arr: [u8; 32] = decrypted
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Ed25519 key length"))?;
        decrypted.zeroize(); // Zero decrypted raw bytes
        let signing_key = SigningKey::from_bytes(&key_bytes_arr);
        let verifying_key = signing_key.verifying_key();

        // Decrypt X25519 secret key (backward-compatible: if missing, regenerate)
        let encryption_secret =
            if !stored.encrypted_x25519.is_empty() && !stored.nonce_x25519.is_empty() {
                let nonce_x = Nonce::from_slice(&stored.nonce_x25519);
                let decrypted_x = cipher
                    .decrypt(nonce_x, stored.encrypted_x25519.as_ref())
                    .map_err(|_| anyhow::anyhow!("X25519 decryption failed"))?;
                let x_bytes: [u8; 32] = decrypted_x
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid X25519 key length"))?;
                StaticSecret::from(x_bytes)
            } else {
                // Older identity file without X25519 — derive from signing key deterministically
                tracing::warn!(
                    "Old identity format: deriving X25519 from Ed25519 (re-save to upgrade)"
                );
                let mut hasher = Sha256::new();
                hasher.update(b"Qypha-X25519-Derived-v1");
                hasher.update(signing_key.as_bytes());
                let derived = hasher.finalize();
                let mut x_bytes = [0u8; 32];
                x_bytes.copy_from_slice(&derived);
                StaticSecret::from(x_bytes)
            };

        let encryption_public = X25519PublicKey::from(&encryption_secret);
        let derived_did = derive_did_from_verifying_key(&verifying_key);
        if stored.did != derived_did {
            anyhow::bail!(
                "Stored DID '{}' does not match decrypted Ed25519 identity '{}'",
                stored.did,
                derived_did
            );
        }
        if stored.public_key != verifying_key.as_bytes() {
            anyhow::bail!("Stored Ed25519 public key does not match decrypted signing key");
        }

        // Decrypt Kyber secret key (backward-compatible: if missing or wrong size, generate new)
        let (kyber_public, kyber_secret) = if !stored.encrypted_kyber_secret.is_empty()
            && !stored.nonce_kyber.is_empty()
        {
            let nonce_k = Nonce::from_slice(&stored.nonce_kyber);
            let mut decrypted_k = cipher
                .decrypt(nonce_k, stored.encrypted_kyber_secret.as_ref())
                .map_err(|_| anyhow::anyhow!("Kyber secret decryption failed"))?;

            // Check if key sizes match current Kyber level (1024)
            // Old Kyber-768: public=1184, secret=2400
            // New Kyber-1024: public=1568, secret=3168
            if stored.kyber_public_key.len() != pqc_kyber::KYBER_PUBLICKEYBYTES
                || decrypted_k.len() != pqc_kyber::KYBER_SECRETKEYBYTES
            {
                tracing::warn!(
                    old_pub = stored.kyber_public_key.len(),
                    old_sec = decrypted_k.len(),
                    new_pub = pqc_kyber::KYBER_PUBLICKEYBYTES,
                    new_sec = pqc_kyber::KYBER_SECRETKEYBYTES,
                    "Kyber-768 keys detected — upgrading to Kyber-1024 (re-save to persist)"
                );
                decrypted_k.zeroize();
                let mut rng = rand::thread_rng();
                let keys =
                    pqc_kyber::keypair(&mut rng).expect("Kyber-1024 keygen should never fail");
                (keys.public.to_vec(), keys.secret.to_vec())
            } else {
                let ks = decrypted_k.clone();
                decrypted_k.zeroize();
                (stored.kyber_public_key.clone(), ks)
            }
        } else {
            // Old identity without Kyber — generate new Kyber-1024 keys
            tracing::warn!(
                "Old identity format: generating new Kyber-1024 keypair (re-save to upgrade)"
            );
            let mut rng = rand::thread_rng();
            let keys = pqc_kyber::keypair(&mut rng).expect("Kyber-1024 keygen should never fail");
            (keys.public.to_vec(), keys.secret.to_vec())
        };

        let _signing_key_guard = zeroize::Zeroizing::new(signing_key.to_bytes());
        let _encryption_secret_guard = zeroize::Zeroizing::new(encryption_secret.to_bytes());
        let _kyber_secret_guard = zeroize::Zeroizing::new(kyber_secret.clone());

        tracing::info!(did = %stored.did, "Agent identity loaded (Ed25519 + X25519 + Kyber-1024)");

        Ok(Self {
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
            did: derived_did,
            metadata: stored.metadata,
            kyber_public,
            kyber_secret,
            _signing_key_guard,
            _encryption_secret_guard,
            _kyber_secret_guard,
        })
    }
}

/// Derive the canonical Qypha DID from an Ed25519 verifying key.
///
/// The DID depends only on the cryptographic public key, never on the
/// agent display name, passphrase, machine identity, or location.
pub fn derive_did_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    format!("{DID_METHOD_PREFIX}{}", hex::encode(hash))
}

pub fn is_valid_did(value: &str) -> bool {
    let Some(fingerprint) = value.strip_prefix(DID_METHOD_PREFIX) else {
        return false;
    };
    fingerprint.len() == DID_FINGERPRINT_HEX_LEN
        && fingerprint
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted_key: Vec<u8>,
    #[serde(default)]
    nonce_x25519: Vec<u8>,
    #[serde(default)]
    encrypted_x25519: Vec<u8>,
    // Post-quantum Kyber-1024 fields (backward-compatible: empty = old format, 768-size = auto-upgrade)
    #[serde(default)]
    nonce_kyber: Vec<u8>,
    #[serde(default)]
    encrypted_kyber_secret: Vec<u8>,
    #[serde(default)]
    kyber_public_key: Vec<u8>,
    did: String,
    public_key: Vec<u8>,
    #[serde(default)]
    encryption_public_key: Vec<u8>,
    metadata: AgentMetadata,
    /// Argon2 parameter version: 0/absent = default (t=2,m=19MB,p=1), 2 = military (t=4,m=256MB,p=4)
    #[serde(default)]
    argon2_version: u8,
}

/// Military-grade Argon2id parameters for key derivation.
///
/// t=4 iterations, m=256MB memory, p=4 parallelism.
/// Makes brute-force attacks require ~1GB of RAM and several seconds per attempt,
/// rendering GPU/ASIC attacks computationally infeasible.
fn military_grade_argon2() -> argon2::Argon2<'static> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(256 * 1024, 4, 4, Some(32)).expect("valid Argon2 params"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_keypair() {
        let kp = AgentKeyPair::generate("TestAgent", "finance");
        assert!(kp.did.starts_with(DID_METHOD_PREFIX));
        assert_eq!(
            kp.did.len(),
            DID_METHOD_PREFIX.len() + DID_FINGERPRINT_HEX_LEN
        );
        assert_eq!(kp.metadata.role, "finance");
    }

    #[test]
    fn test_did_format_validator_accepts_canonical_ids() {
        let kp = AgentKeyPair::generate("Validator", "agent");
        assert!(is_valid_did(&kp.did));
        assert!(!is_valid_did("did:nxf:XYZ"));
        assert!(!is_valid_did("did:other:0123"));
    }

    #[test]
    fn test_did_uniqueness() {
        let kp1 = AgentKeyPair::generate("Agent1", "finance");
        let kp2 = AgentKeyPair::generate("Agent2", "hr");
        assert_ne!(kp1.did, kp2.did);
    }

    #[test]
    fn test_same_name_still_generates_distinct_dids() {
        let kp1 = AgentKeyPair::generate("agent1", "finance");
        let kp2 = AgentKeyPair::generate("agent1", "finance");
        assert_ne!(kp1.did, kp2.did);
    }

    #[test]
    fn test_x25519_keypairs_unique() {
        let kp1 = AgentKeyPair::generate("A1", "finance");
        let kp2 = AgentKeyPair::generate("A2", "hr");
        assert_ne!(kp1.x25519_public_key_bytes(), kp2.x25519_public_key_bytes());
    }

    #[test]
    fn test_save_and_load() {
        let kp = AgentKeyPair::generate("TestAgent", "ds");
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        kp.save_to_file(&path, "test_passphrase_123").unwrap();
        let loaded = AgentKeyPair::load_from_file(&path, "test_passphrase_123").unwrap();

        assert_eq!(kp.did, loaded.did);
        assert_eq!(kp.signing_key.as_bytes(), loaded.signing_key.as_bytes());
        assert_eq!(
            kp.x25519_public_key_bytes(),
            loaded.x25519_public_key_bytes()
        );
        assert_eq!(
            kp.x25519_secret_key_bytes(),
            loaded.x25519_secret_key_bytes()
        );
    }

    #[test]
    fn test_same_name_and_same_passphrase_still_generate_distinct_dids() {
        let kp1 = AgentKeyPair::generate("agent1", "finance");
        let kp2 = AgentKeyPair::generate("agent1", "finance");
        let tmp1 = NamedTempFile::new().unwrap();
        let tmp2 = NamedTempFile::new().unwrap();
        let passphrase = "same-passphrase-for-both";

        kp1.save_to_file(tmp1.path(), passphrase).unwrap();
        kp2.save_to_file(tmp2.path(), passphrase).unwrap();

        let loaded1 = AgentKeyPair::load_from_file(tmp1.path(), passphrase).unwrap();
        let loaded2 = AgentKeyPair::load_from_file(tmp2.path(), passphrase).unwrap();

        assert_ne!(loaded1.did, loaded2.did);
        assert_ne!(
            loaded1.verifying_key.as_bytes(),
            loaded2.verifying_key.as_bytes()
        );
    }

    #[test]
    fn test_did_derivation_is_deterministic_for_same_verifying_key() {
        let kp = AgentKeyPair::generate("Deterministic", "agent");
        let did_a = derive_did_from_verifying_key(&kp.verifying_key);
        let did_b = derive_did_from_verifying_key(&kp.verifying_key);
        assert_eq!(did_a, did_b);
    }

    #[test]
    fn test_large_batch_generated_dids_are_unique() {
        let mut seen = HashSet::new();
        for idx in 0..4096 {
            let kp = AgentKeyPair::generate(&format!("agent-{idx}"), "agent");
            assert!(
                seen.insert(kp.did.clone()),
                "duplicate DID generated in batch test: {}",
                kp.did
            );
        }
    }

    #[test]
    fn test_load_rejects_did_tampering() {
        let kp = AgentKeyPair::generate("Tamper", "agent");
        let tmp = NamedTempFile::new().unwrap();
        kp.save_to_file(tmp.path(), "tamper-check").unwrap();

        let mut stored: StoredIdentity =
            serde_json::from_str(&std::fs::read_to_string(tmp.path()).unwrap()).unwrap();
        stored.did = format!("{DID_METHOD_PREFIX}{}", "f".repeat(DID_FINGERPRINT_HEX_LEN));
        std::fs::write(tmp.path(), serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

        let error = AgentKeyPair::load_from_file(tmp.path(), "tamper-check")
            .err()
            .expect("tampered DID should be rejected");
        assert!(error.to_string().contains("Stored DID"));
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let kp = AgentKeyPair::generate("TestAgent", "ds");
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        kp.save_to_file(&path, "correct_pass").unwrap();
        let result = AgentKeyPair::load_from_file(&path, "wrong_pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_kyber_keypair_generated() {
        let kp = AgentKeyPair::generate("KyberAgent", "finance");
        assert_eq!(kp.kyber_public.len(), pqc_kyber::KYBER_PUBLICKEYBYTES);
        assert_eq!(kp.kyber_secret.len(), pqc_kyber::KYBER_SECRETKEYBYTES);
    }

    #[test]
    fn test_kyber_save_and_load() {
        let kp = AgentKeyPair::generate("KyberSaveTest", "ds");
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        kp.save_to_file(&path, "kyber_pass_123").unwrap();
        let loaded = AgentKeyPair::load_from_file(&path, "kyber_pass_123").unwrap();

        assert_eq!(kp.kyber_public, loaded.kyber_public);
        assert_eq!(kp.kyber_secret, loaded.kyber_secret);
    }

    #[test]
    fn test_public_identity_has_kyber() {
        let kp = AgentKeyPair::generate("PQCAgent", "exec");
        let pub_id = kp.public_identity();
        assert!(pub_id.kyber_public_key_hex.is_some());
        let kyber_hex = pub_id.kyber_public_key_hex.unwrap();
        assert_eq!(kyber_hex.len(), pqc_kyber::KYBER_PUBLICKEYBYTES * 2); // hex = 2x bytes
    }
}

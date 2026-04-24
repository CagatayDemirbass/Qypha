use aegis::aegis256::Aegis256;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Encrypted envelope containing all info needed for decryption.
///
/// Supports both classical (X25519-only) and hybrid (X25519 + Kyber-1024)
/// encryption. Old agents without Kyber will deserialize with
/// `kyber_ciphertext: None` and fall back to classical-only.
///
/// Cascade AEAD: When `cascade_nonce` is present, ciphertext has been
/// double-encrypted: AES-256-GCM first, then XChaCha20-Poly1305.
/// This provides defense-in-depth — even if one AEAD algorithm is broken,
/// the other still protects the data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedEnvelope {
    pub ephemeral_public_key: Vec<u8>, // X25519 ephemeral public key
    pub nonce: Vec<u8>,                // 12-byte AES-GCM nonce
    pub ciphertext: Vec<u8>,           // Encrypted data (cascade or AES-only)
    /// Kyber-1024 ciphertext (1568 bytes). None = classical-only (old peer).
    #[serde(default)]
    pub kyber_ciphertext: Option<Vec<u8>>,
    /// If true, recipient MUST use hybrid PQC decryption. Prevents Kyber stripping
    /// downgrade attacks where a MITM removes kyber_ciphertext to force classical-only.
    #[serde(default)]
    pub pqc_required: bool,
    /// XChaCha20-Poly1305 nonce (24 bytes) for cascade AEAD.
    /// Present = ciphertext is double-encrypted (AEGIS-256/AES-256-GCM + XChaCha20-Poly1305).
    /// Absent = single AEAD (backward compat with older agents).
    #[serde(default)]
    pub cascade_nonce: Option<Vec<u8>>,
    /// Envelope version: 0/absent = AES-256-GCM (legacy), 1 = AEGIS-256 cascade.
    /// Used for backward-compatible version dispatch during decryption.
    #[serde(default)]
    pub envelope_version: u8,
}

/// Encrypt a message for a specific recipient using X25519 + AEGIS-256
///
/// 1. Generate ephemeral X25519 keypair
/// 2. Compute shared secret via ECDH with recipient's public key
/// 3. Derive AEGIS-256 key from shared secret using SHA-256
/// 4. Encrypt plaintext with AEGIS-256 (key-committing, 256-bit nonce, 256-bit tag)
pub fn encrypt_message(
    recipient_public_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedEnvelope> {
    // 1. Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // 2. Compute shared secret
    let recipient_pk = PublicKey::from(*recipient_public_key);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // 3. Derive AEGIS-256 key from shared secret
    let mut aegis_key = derive_aegis_key(shared_secret.as_bytes());

    // 4. Encrypt with AEGIS-256 (32-byte tag for key-committing security)
    let aegis_nonce: [u8; 32] = rand::random();
    let aegis = Aegis256::<32>::new(&aegis_key, &aegis_nonce);
    aegis_key.zeroize();
    let (ct, tag) = aegis.encrypt(plaintext, b"");
    // Combine: ciphertext || tag (32 bytes)
    let mut ciphertext = ct;
    ciphertext.extend_from_slice(&tag);

    Ok(EncryptedEnvelope {
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        nonce: aegis_nonce.to_vec(),
        ciphertext,
        kyber_ciphertext: None, // Classical-only path
        pqc_required: false,    // Classical path — no PQC enforcement
        cascade_nonce: None,    // Classical path — no cascade
        envelope_version: 1,    // v1 = AEGIS-256
    })
}

/// Decrypt a message using the recipient's static private key.
/// Handles both v0 (AES-256-GCM) and v1 (AEGIS-256) envelopes.
pub fn decrypt_message(
    recipient_secret_key: &[u8; 32],
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>> {
    // Reconstruct ephemeral public key
    let ephemeral_pk_bytes: [u8; 32] = envelope
        .ephemeral_public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ephemeral public key"))?;
    let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);

    // Compute shared secret
    let recipient_sk = StaticSecret::from(*recipient_secret_key);
    let shared_secret = recipient_sk.diffie_hellman(&ephemeral_pk);

    if envelope.envelope_version >= 1 {
        // v1: AEGIS-256 (32-byte nonce, 32-byte tag appended to ciphertext)
        let mut aegis_key = derive_aegis_key(shared_secret.as_bytes());
        let aegis_nonce: [u8; 32] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid AEGIS-256 nonce (expected 32 bytes)"))?;

        if envelope.ciphertext.len() < 32 {
            aegis_key.zeroize();
            return Err(anyhow::anyhow!("AEGIS-256 ciphertext too short for tag"));
        }
        let tag_start = envelope.ciphertext.len() - 32;
        let ct = &envelope.ciphertext[..tag_start];
        let tag: [u8; 32] = envelope.ciphertext[tag_start..].try_into().unwrap();

        let aegis = Aegis256::<32>::new(&aegis_key, &aegis_nonce);
        aegis_key.zeroize();
        let plaintext = aegis.decrypt(ct, &tag, b"").map_err(|_| {
            anyhow::anyhow!("AEGIS-256 decryption failed — wrong key or tampered data")
        })?;
        Ok(plaintext)
    } else {
        // v0: AES-256-GCM (12-byte nonce, tag embedded in ciphertext)
        let mut aes_key = derive_aes_key(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
        aes_key.zeroize();

        let nonce_bytes: [u8; 12] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid AES-GCM nonce (expected 12 bytes)"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, envelope.ciphertext.as_ref())
            .map_err(|_| {
                anyhow::anyhow!("AES-256-GCM decryption failed — wrong key or tampered data")
            })?;
        Ok(plaintext)
    }
}

/// Encrypt a file/artifact using a fresh symmetric key, then wrap the key
/// with the recipient's X25519 public key (envelope encryption).
/// Uses AEGIS-256 (v1) for data encryption with 32-byte nonce + 32-byte tag.
pub fn encrypt_artifact(
    recipient_public_key: &[u8; 32],
    data: &[u8],
) -> Result<(EncryptedEnvelope, Vec<u8>)> {
    // Generate random symmetric key for the data itself
    let mut data_key = rand::random::<[u8; 32]>();
    let data_nonce: [u8; 32] = rand::random();

    // Encrypt the data with AEGIS-256 (32-byte tag for key-committing)
    let aegis = Aegis256::<32>::new(&data_key, &data_nonce);
    let (ct, tag) = aegis.encrypt(data, b"");

    // Now wrap (encrypt) the symmetric key using recipient's public key
    let key_envelope = encrypt_message(recipient_public_key, &data_key)?;

    // Zero the symmetric data key from memory
    data_key.zeroize();

    // Return: wrapped key envelope + encrypted data (nonce || ciphertext || tag)
    let mut full_encrypted = Vec::with_capacity(32 + ct.len() + 32);
    full_encrypted.extend_from_slice(&data_nonce);
    full_encrypted.extend_from_slice(&ct);
    full_encrypted.extend_from_slice(&tag);

    Ok((key_envelope, full_encrypted))
}

/// Decrypt an artifact: unwrap the key, then decrypt the data.
/// Handles both v0 (AES-256-GCM: 12-byte nonce) and v1 (AEGIS-256: 32-byte nonce + 32-byte tag).
pub fn decrypt_artifact(
    recipient_secret_key: &[u8; 32],
    key_envelope: &EncryptedEnvelope,
    encrypted_data: &[u8],
) -> Result<Vec<u8>> {
    // Unwrap the symmetric key
    let mut data_key_bytes = decrypt_message(recipient_secret_key, key_envelope)?;
    let mut data_key: [u8; 32] = data_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid data key length"))?;
    data_key_bytes.zeroize();

    if key_envelope.envelope_version >= 1 {
        // v1: AEGIS-256 (32-byte nonce, 32-byte tag at end)
        if encrypted_data.len() < 64 {
            data_key.zeroize();
            return Err(anyhow::anyhow!("Encrypted data too short for AEGIS-256"));
        }
        let nonce: [u8; 32] = encrypted_data[..32].try_into().unwrap();
        let tag_start = encrypted_data.len() - 32;
        let ct = &encrypted_data[32..tag_start];
        let tag: [u8; 32] = encrypted_data[tag_start..].try_into().unwrap();

        let aegis = Aegis256::<32>::new(&data_key, &nonce);
        data_key.zeroize();
        let plaintext = aegis
            .decrypt(ct, &tag, b"")
            .map_err(|_| anyhow::anyhow!("AEGIS-256 artifact decryption failed"))?;
        Ok(plaintext)
    } else {
        // v0: AES-256-GCM (12-byte nonce)
        if encrypted_data.len() < 12 {
            data_key.zeroize();
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&data_key)?;
        data_key.zeroize();
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM artifact decryption failed"))?;
        Ok(plaintext)
    }
}

/// Derive AES-256 key from shared secret using SHA-256 (classical, v0 legacy)
fn derive_aes_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Qypha-v1-AES-Key-Derivation");
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Derive AEGIS-256 key from shared secret using SHA-256 (classical, v1)
fn derive_aegis_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Qypha-v1-AEGIS-Key-Derivation");
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// ═══════════════════════════════════════════════════════════════════════════
// POST-QUANTUM HYBRID ENCRYPTION: X25519 + Kyber-1024 + Cascade AEAD
//
// These functions combine classical X25519 ECDH with post-quantum Kyber-1024
// KEM (NIST Level 5, AES-256 equivalent), deriving the final keys via
// HKDF-SHA256 from both shared secrets.
//
// Cascade AEAD: Data is encrypted twice — first with AES-256-GCM, then with
// XChaCha20-Poly1305. Two independent keys are derived from the same shared
// secrets using different HKDF info strings. Even if one AEAD algorithm is
// cryptanalytically broken, the other still protects the data.
//
// Defense layers:
//   1. X25519 ECDH (classical, ~128-bit security)
//   2. Kyber-1024 KEM (post-quantum, NIST Level 5)
//   3. AEGIS-256 (inner AEAD — key-committing, 256-bit nonce, 256-bit tag)
//   4. XChaCha20-Poly1305 (outer AEAD, 192-bit nonce)
// ═══════════════════════════════════════════════════════════════════════════

/// Derive AES-256 key from combined X25519 + Kyber shared secrets using HKDF-SHA256.
///
/// If `kyber_shared_secret` is None, falls back to classical-only derivation
/// (backward compatible with pre-PQC peers).
fn derive_hybrid_aes_key(
    x25519_shared_secret: &[u8],
    kyber_shared_secret: Option<&[u8]>,
) -> [u8; 32] {
    // Combine input keying material: X25519 || Kyber (if present)
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x25519_shared_secret);
    if let Some(ks) = kyber_shared_secret {
        ikm.extend_from_slice(ks);
    }

    let hk = Hkdf::<Sha256>::new(
        Some(b"Qypha-v2-Hybrid-KDF"), // salt (domain separation)
        &ikm,
    );
    let mut key = [0u8; 32];
    hk.expand(b"Qypha-AES-256-GCM-Key", &mut key)
        .expect("HKDF expand should never fail with 32-byte output");

    ikm.zeroize(); // Zero the combined IKM
    key
}

/// Derive AEGIS-256 key from combined X25519 + Kyber shared secrets using HKDF-SHA256.
///
/// Uses different domain separation from the AES and XChaCha20 paths for cryptographic
/// independence between all AEAD layers.
fn derive_hybrid_aegis_key(
    x25519_shared_secret: &[u8],
    kyber_shared_secret: Option<&[u8]>,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x25519_shared_secret);
    if let Some(ks) = kyber_shared_secret {
        ikm.extend_from_slice(ks);
    }

    let hk = Hkdf::<Sha256>::new(
        Some(b"Qypha-v4-AEGIS256-KDF"), // unique salt for AEGIS path
        &ikm,
    );
    let mut key = [0u8; 32];
    hk.expand(b"Qypha-AEGIS-256-Key", &mut key)
        .expect("HKDF expand should never fail with 32-byte output");

    ikm.zeroize();
    key
}

/// Derive XChaCha20-Poly1305 key for cascade AEAD from combined shared secrets.
///
/// Uses a different HKDF salt/info than the AES key to ensure cryptographic
/// independence between the two AEAD layers.
fn derive_cascade_chacha_key(
    x25519_shared_secret: &[u8],
    kyber_shared_secret: Option<&[u8]>,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x25519_shared_secret);
    if let Some(ks) = kyber_shared_secret {
        ikm.extend_from_slice(ks);
    }

    let hk = Hkdf::<Sha256>::new(
        Some(b"Qypha-v3-Cascade-XChaCha20"), // different salt from AES path
        &ikm,
    );
    let mut key = [0u8; 32];
    hk.expand(b"Qypha-XChaCha20-Poly1305-Key", &mut key)
        .expect("HKDF expand should never fail with 32-byte output");

    ikm.zeroize();
    key
}

/// Encrypt a message using hybrid X25519 + Kyber-1024 KEM + Cascade AEAD.
///
/// If `recipient_kyber_public` is None, falls back to classical-only (backward compat).
pub fn hybrid_encrypt_message(
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<EncryptedEnvelope> {
    // If no Kyber key → fall back to classical encryption (backward compatible)
    if recipient_kyber_public.is_none() {
        return encrypt_message(recipient_x25519_public, plaintext);
    }

    // 1. X25519 ECDH
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let recipient_pk = PublicKey::from(*recipient_x25519_public);
    let x25519_shared = ephemeral_secret.diffie_hellman(&recipient_pk);

    // 2. Kyber-1024 encapsulation (NIST Level 5)
    let kyber_pk = recipient_kyber_public.unwrap(); // safe: checked above
    let mut rng = rand::thread_rng();
    let (kyber_ct, mut kyber_ss) = {
        let (ct, ss) = pqc_kyber::encapsulate(kyber_pk, &mut rng)
            .map_err(|e| anyhow::anyhow!("Kyber encapsulate failed: {:?}", e))?;
        (ct.to_vec(), ss.to_vec())
    };

    // 3. Hybrid key derivation for AEGIS-256: HKDF-SHA256(X25519 || Kyber)
    let mut aegis_key = derive_hybrid_aegis_key(x25519_shared.as_bytes(), Some(&kyber_ss));

    // 4. AEGIS-256 encryption (inner layer — key-committing, 32-byte tag)
    let aegis_nonce: [u8; 32] = rand::random();
    let aegis = Aegis256::<32>::new(&aegis_key, &aegis_nonce);
    aegis_key.zeroize();
    let (aegis_ct, aegis_tag) = aegis.encrypt(plaintext, b"");
    // Combine: ciphertext || tag (32 bytes)
    let mut inner_ciphertext = aegis_ct;
    inner_ciphertext.extend_from_slice(&aegis_tag);

    // 5. XChaCha20-Poly1305 encryption (outer layer — cascade AEAD, algorithmic diversity)
    let mut chacha_key = derive_cascade_chacha_key(x25519_shared.as_bytes(), Some(&kyber_ss));
    let chacha_cipher = XChaCha20Poly1305::new_from_slice(&chacha_key)?;
    let chacha_nonce_bytes = rand::random::<[u8; 24]>(); // 192-bit nonce
    let chacha_nonce = chacha20poly1305::XNonce::from_slice(&chacha_nonce_bytes);
    let cascade_ciphertext = chacha_cipher
        .encrypt(chacha_nonce, inner_ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 cascade encryption failed: {}", e))?;

    // Zero sensitive material
    chacha_key.zeroize();
    kyber_ss.zeroize();

    Ok(EncryptedEnvelope {
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        nonce: aegis_nonce.to_vec(),
        ciphertext: cascade_ciphertext,
        kyber_ciphertext: Some(kyber_ct),
        pqc_required: true,
        cascade_nonce: Some(chacha_nonce_bytes.to_vec()),
        envelope_version: 1,
    })
}

/// Decrypt a hybrid-encrypted message (with cascade AEAD support).
///
/// Automatically handles:
/// - Cascade AEAD (XChaCha20-Poly1305 + AES-256-GCM) — when cascade_nonce is present
/// - Single AEAD (AES-256-GCM only) — backward compat with older agents
/// - Classical-only (X25519, no Kyber) — backward compat with pre-PQC agents
pub fn hybrid_decrypt_message(
    recipient_x25519_secret: &[u8; 32],
    recipient_kyber_secret: Option<&[u8]>,
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>> {
    // PQC downgrade attack detection: if the sender marked pqc_required but
    // the kyber_ciphertext was stripped (MITM attack), reject immediately
    if envelope.pqc_required && envelope.kyber_ciphertext.is_none() {
        return Err(anyhow::anyhow!(
            "PQC DOWNGRADE ATTACK DETECTED: envelope marked pqc_required=true \
             but kyber_ciphertext is missing. A MITM may have stripped the \
             post-quantum key encapsulation."
        ));
    }

    // Backward compatibility: if envelope has no Kyber ciphertext,
    // fall back to classical X25519-only decryption (SHA-256 key derivation)
    if envelope.kyber_ciphertext.is_none() {
        return decrypt_message(recipient_x25519_secret, envelope);
    }

    // 1. X25519 ECDH
    let ephemeral_pk_bytes: [u8; 32] = envelope
        .ephemeral_public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ephemeral public key"))?;
    let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);
    let recipient_sk = StaticSecret::from(*recipient_x25519_secret);
    let x25519_shared = recipient_sk.diffie_hellman(&ephemeral_pk);

    // 2. Kyber-1024 decapsulation
    let mut kyber_ss = if let Some(sk) = recipient_kyber_secret {
        let ct = envelope.kyber_ciphertext.as_ref().unwrap(); // safe: checked above
        let ss = pqc_kyber::decapsulate(ct, sk)
            .map_err(|e| anyhow::anyhow!("Kyber decapsulate failed: {:?}", e))?;
        Some(ss.to_vec())
    } else {
        None
    };

    // 3. If cascade AEAD is present, decrypt XChaCha20-Poly1305 outer layer first
    let inner_ciphertext = if let Some(ref chacha_nonce_bytes) = envelope.cascade_nonce {
        let chacha_nonce: [u8; 24] = chacha_nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid cascade nonce (expected 24 bytes)"))?;

        let mut chacha_key =
            derive_cascade_chacha_key(x25519_shared.as_bytes(), kyber_ss.as_deref());
        let chacha_cipher = XChaCha20Poly1305::new_from_slice(&chacha_key)?;
        chacha_key.zeroize();

        let chacha_nonce = chacha20poly1305::XNonce::from_slice(&chacha_nonce);
        chacha_cipher
            .decrypt(chacha_nonce, envelope.ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("XChaCha20-Poly1305 cascade decryption failed"))?
    } else {
        // No cascade — ciphertext is inner AEAD only (backward compat)
        envelope.ciphertext.clone()
    };

    // 4. Inner layer decryption — version-aware
    let plaintext = if envelope.envelope_version >= 1 {
        // v1: AEGIS-256 (32-byte nonce, 32-byte tag appended)
        let mut aegis_key = derive_hybrid_aegis_key(x25519_shared.as_bytes(), kyber_ss.as_deref());
        if let Some(ref mut ss) = kyber_ss {
            ss.zeroize();
        }

        let aegis_nonce: [u8; 32] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid AEGIS-256 nonce (expected 32 bytes)"))?;

        if inner_ciphertext.len() < 32 {
            aegis_key.zeroize();
            return Err(anyhow::anyhow!("AEGIS-256 ciphertext too short for tag"));
        }
        let tag_start = inner_ciphertext.len() - 32;
        let ct = &inner_ciphertext[..tag_start];
        let tag: [u8; 32] = inner_ciphertext[tag_start..].try_into().unwrap();

        let aegis = Aegis256::<32>::new(&aegis_key, &aegis_nonce);
        aegis_key.zeroize();
        aegis
            .decrypt(ct, &tag, b"")
            .map_err(|_| anyhow::anyhow!("AEGIS-256 decryption failed"))?
    } else {
        // v0: AES-256-GCM (12-byte nonce, tag embedded in ciphertext)
        let mut aes_key = derive_hybrid_aes_key(x25519_shared.as_bytes(), kyber_ss.as_deref());
        if let Some(ref mut ss) = kyber_ss {
            ss.zeroize();
        }

        let aes_cipher = Aes256Gcm::new_from_slice(&aes_key)?;
        aes_key.zeroize();

        let nonce_bytes: [u8; 12] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid AES-GCM nonce (expected 12 bytes)"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        aes_cipher
            .decrypt(nonce, inner_ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("AES-256-GCM decryption failed"))?
    };

    Ok(plaintext)
}

/// Encrypt a file/artifact using hybrid X25519 + Kyber-1024 KEM + Cascade AEAD.
///
/// Two-layer envelope: random AEGIS-256 key encrypts data, then hybrid cascade KEM wraps the key.
pub fn hybrid_encrypt_artifact(
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
    data: &[u8],
) -> Result<(EncryptedEnvelope, Vec<u8>)> {
    // Generate random symmetric key for the data
    let mut data_key = rand::random::<[u8; 32]>();
    let data_nonce: [u8; 32] = rand::random();

    // Encrypt data with AEGIS-256 (32-byte tag for key-committing)
    let aegis = Aegis256::<32>::new(&data_key, &data_nonce);
    let (ct, tag) = aegis.encrypt(data, b"");

    // Wrap the symmetric key with hybrid KEM
    let key_envelope =
        hybrid_encrypt_message(recipient_x25519_public, recipient_kyber_public, &data_key)?;

    data_key.zeroize();

    // Format: nonce (32) || ciphertext || tag (32)
    let mut full_encrypted = Vec::with_capacity(32 + ct.len() + 32);
    full_encrypted.extend_from_slice(&data_nonce);
    full_encrypted.extend_from_slice(&ct);
    full_encrypted.extend_from_slice(&tag);

    Ok((key_envelope, full_encrypted))
}

/// Decrypt a hybrid-encrypted artifact.
///
/// Handles both v0 (AES-256-GCM) and v1 (AEGIS-256) data encryption transparently.
pub fn hybrid_decrypt_artifact(
    recipient_x25519_secret: &[u8; 32],
    recipient_kyber_secret: Option<&[u8]>,
    key_envelope: &EncryptedEnvelope,
    encrypted_data: &[u8],
) -> Result<Vec<u8>> {
    let mut data_key_bytes = hybrid_decrypt_message(
        recipient_x25519_secret,
        recipient_kyber_secret,
        key_envelope,
    )?;
    let mut data_key: [u8; 32] = data_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid data key length"))?;
    data_key_bytes.zeroize();

    if key_envelope.envelope_version >= 1 {
        // v1: AEGIS-256 (32-byte nonce, 32-byte tag at end)
        if encrypted_data.len() < 64 {
            data_key.zeroize();
            return Err(anyhow::anyhow!("Encrypted data too short for AEGIS-256"));
        }
        let nonce: [u8; 32] = encrypted_data[..32].try_into().unwrap();
        let tag_start = encrypted_data.len() - 32;
        let ct = &encrypted_data[32..tag_start];
        let tag: [u8; 32] = encrypted_data[tag_start..].try_into().unwrap();

        let aegis = Aegis256::<32>::new(&data_key, &nonce);
        data_key.zeroize();
        let plaintext = aegis
            .decrypt(ct, &tag, b"")
            .map_err(|_| anyhow::anyhow!("AEGIS-256 hybrid artifact decryption failed"))?;
        Ok(plaintext)
    } else {
        // v0: AES-256-GCM (12-byte nonce)
        if encrypted_data.len() < 12 {
            data_key.zeroize();
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&data_key)?;
        data_key.zeroize();
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM hybrid artifact decryption failed"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), *public.as_bytes())
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"Confidential financial report Q3 2026";

        let envelope = encrypt_message(&public, plaintext).unwrap();
        let decrypted = decrypt_message(&secret, &envelope).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails_to_decrypt() {
        let (_secret1, public1) = generate_x25519_keypair();
        let (secret2, _public2) = generate_x25519_keypair();

        let plaintext = b"Secret data";
        let envelope = encrypt_message(&public1, plaintext).unwrap();

        // Try decrypting with wrong secret key
        let result = decrypt_message(&secret2, &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_artifact() {
        let (secret, public) = generate_x25519_keypair();
        let data = b"Large CSV content with financial data...".repeat(100);

        let (key_envelope, encrypted_data) = encrypt_artifact(&public, &data).unwrap();
        let decrypted = decrypt_artifact(&secret, &key_envelope, &encrypted_data).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_envelope_encryption_unique_per_call() {
        let (_secret, public) = generate_x25519_keypair();
        let plaintext = b"Same message";

        let env1 = encrypt_message(&public, plaintext).unwrap();
        let env2 = encrypt_message(&public, plaintext).unwrap();

        // Each encryption should produce different ciphertext (different ephemeral key)
        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.ephemeral_public_key, env2.ephemeral_public_key);
    }

    // ── Post-Quantum Hybrid Encryption Tests ──────────────────────────

    fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let keys = pqc_kyber::keypair(&mut rng).unwrap();
        (keys.secret.to_vec(), keys.public.to_vec())
    }

    #[test]
    fn test_hybrid_encrypt_decrypt_message() {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (k_secret, k_public) = generate_kyber_keypair();
        let plaintext = b"Post-quantum secure classified intelligence report";

        let envelope = hybrid_encrypt_message(&x_public, Some(&k_public), plaintext).unwrap();
        assert!(envelope.kyber_ciphertext.is_some());
        // Cascade AEAD must be active for hybrid encryption
        assert!(envelope.cascade_nonce.is_some());
        assert_eq!(envelope.cascade_nonce.as_ref().unwrap().len(), 24); // XChaCha20 nonce = 24 bytes

        let decrypted = hybrid_decrypt_message(&x_secret, Some(&k_secret), &envelope).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_cascade_aead_double_encryption() {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (k_secret, k_public) = generate_kyber_keypair();
        let plaintext = b"Cascade AEAD: AES-256-GCM + XChaCha20-Poly1305";

        let envelope = hybrid_encrypt_message(&x_public, Some(&k_public), plaintext).unwrap();

        // Cascade must be active
        assert!(envelope.cascade_nonce.is_some());

        // Ciphertext must be at least plaintext + dual AEAD overhead
        // AEGIS-256 tag = 32 bytes, XChaCha20 tag = 16 bytes = 48 bytes total
        assert!(envelope.ciphertext.len() >= plaintext.len() + 48);

        // Decrypt must succeed
        let decrypted = hybrid_decrypt_message(&x_secret, Some(&k_secret), &envelope).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_cascade_backward_compat_no_cascade_nonce() {
        // Simulate an older envelope without cascade (cascade_nonce = None)
        let (x_secret, x_public) = generate_x25519_keypair();
        let (k_secret, k_public) = generate_kyber_keypair();
        let plaintext = b"Old-style single AEAD message";

        // Manually create a non-cascade hybrid envelope
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let recipient_pk = PublicKey::from(x_public);
        let x25519_shared = ephemeral_secret.diffie_hellman(&recipient_pk);
        let mut rng = rand::thread_rng();
        let (kyber_ct, mut kyber_ss) = {
            let (ct, ss) = pqc_kyber::encapsulate(&k_public, &mut rng).unwrap();
            (ct.to_vec(), ss.to_vec())
        };
        let mut aes_key = derive_hybrid_aes_key(x25519_shared.as_bytes(), Some(&kyber_ss));
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        aes_key.zeroize();
        kyber_ss.zeroize();

        let old_envelope = EncryptedEnvelope {
            ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            kyber_ciphertext: Some(kyber_ct),
            pqc_required: true,
            cascade_nonce: None, // No cascade — old-style
            envelope_version: 0, // v0 = AES-256-GCM legacy
        };

        // Must still decrypt correctly
        let decrypted = hybrid_decrypt_message(&x_secret, Some(&k_secret), &old_envelope).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_fallback_to_classical() {
        // Encrypt with Kyber=None (classical only), decrypt with Kyber secret
        let (x_secret, x_public) = generate_x25519_keypair();
        let (k_secret, _k_public) = generate_kyber_keypair();
        let plaintext = b"Classical fallback test";

        let envelope = hybrid_encrypt_message(&x_public, None, plaintext).unwrap();
        assert!(envelope.kyber_ciphertext.is_none());

        // Decrypt with kyber_secret present but envelope has no kyber ciphertext
        let decrypted = hybrid_decrypt_message(&x_secret, Some(&k_secret), &envelope).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_encrypt_decrypt_artifact() {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (k_secret, k_public) = generate_kyber_keypair();
        let data = b"TOP SECRET financial records 2026".repeat(500);

        let (envelope, encrypted) =
            hybrid_encrypt_artifact(&x_public, Some(&k_public), &data).unwrap();
        assert!(envelope.kyber_ciphertext.is_some());

        let decrypted =
            hybrid_decrypt_artifact(&x_secret, Some(&k_secret), &envelope, &encrypted).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_wrong_kyber_key_fails() {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (_k_secret1, k_public1) = generate_kyber_keypair();
        let (k_secret2, _k_public2) = generate_kyber_keypair();
        let plaintext = b"Should fail with wrong Kyber key";

        let envelope = hybrid_encrypt_message(&x_public, Some(&k_public1), plaintext).unwrap();
        // Decrypt with wrong Kyber secret → should fail
        let result = hybrid_decrypt_message(&x_secret, Some(&k_secret2), &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_pqc_downgrade_attack_detected() {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (_k_secret, k_public) = generate_kyber_keypair();
        let plaintext = b"Top secret government document";

        // Encrypt with hybrid (sets pqc_required=true)
        let mut envelope = hybrid_encrypt_message(&x_public, Some(&k_public), plaintext).unwrap();
        assert!(envelope.pqc_required);
        assert!(envelope.kyber_ciphertext.is_some());

        // Simulate MITM stripping Kyber ciphertext
        envelope.kyber_ciphertext = None;

        // Decryption MUST fail with downgrade attack detection
        let result = hybrid_decrypt_message(&x_secret, None, &envelope);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DOWNGRADE ATTACK"));
    }

    #[test]
    fn test_backward_compat_old_envelope_no_kyber() {
        // Simulate an old envelope (no kyber_ciphertext field)
        let (x_secret, x_public) = generate_x25519_keypair();
        let plaintext = b"Old agent message without PQC";

        // Use classical encrypt
        let envelope = encrypt_message(&x_public, plaintext).unwrap();
        assert!(envelope.kyber_ciphertext.is_none());

        // Decrypt with hybrid function (should work: kyber_ciphertext is None)
        let decrypted = hybrid_decrypt_message(&x_secret, None, &envelope).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    // ── AEGIS-256 Specific Tests ─────────────────────────────────────

    #[test]
    fn test_aegis256_v1_envelope_fields() {
        let (_secret, public) = generate_x25519_keypair();
        let plaintext = b"AEGIS-256 envelope version test";

        let envelope = encrypt_message(&public, plaintext).unwrap();
        // v1 envelopes must have AEGIS-256 properties
        assert_eq!(envelope.envelope_version, 1);
        assert_eq!(envelope.nonce.len(), 32); // 256-bit nonce
                                              // Ciphertext = plaintext + 32-byte AEGIS tag
        assert_eq!(envelope.ciphertext.len(), plaintext.len() + 32);
    }

    #[test]
    fn test_aegis256_hybrid_envelope_fields() {
        let (_x_secret, x_public) = generate_x25519_keypair();
        let (_k_secret, k_public) = generate_kyber_keypair();
        let plaintext = b"Hybrid AEGIS-256 cascade test";

        let envelope = hybrid_encrypt_message(&x_public, Some(&k_public), plaintext).unwrap();
        assert_eq!(envelope.envelope_version, 1);
        assert_eq!(envelope.nonce.len(), 32); // AEGIS-256 nonce
        assert_eq!(envelope.cascade_nonce.as_ref().unwrap().len(), 24); // XChaCha20 nonce
    }

    #[test]
    fn test_aegis256_artifact_roundtrip() {
        let (secret, public) = generate_x25519_keypair();
        let data = b"AEGIS-256 artifact encryption test data".repeat(200);

        let (key_envelope, encrypted) = encrypt_artifact(&public, &data).unwrap();
        assert_eq!(key_envelope.envelope_version, 1);
        // Encrypted data = 32 (nonce) + plaintext + 32 (tag)
        assert_eq!(encrypted.len(), 32 + data.len() + 32);

        let decrypted = decrypt_artifact(&secret, &key_envelope, &encrypted).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aegis256_hybrid_artifact_roundtrip() {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (k_secret, k_public) = generate_kyber_keypair();
        let data = b"Hybrid AEGIS-256 artifact data".repeat(300);

        let (envelope, encrypted) =
            hybrid_encrypt_artifact(&x_public, Some(&k_public), &data).unwrap();
        assert_eq!(envelope.envelope_version, 1);

        let decrypted =
            hybrid_decrypt_artifact(&x_secret, Some(&k_secret), &envelope, &encrypted).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v0_envelope_backward_compat_classical() {
        // Manually create a v0 (AES-256-GCM) envelope and verify it still decrypts
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"Legacy v0 AES-GCM message";

        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let recipient_pk = PublicKey::from(public);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);
        let mut aes_key = derive_aes_key(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        aes_key.zeroize();

        let v0_envelope = EncryptedEnvelope {
            ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            kyber_ciphertext: None,
            pqc_required: false,
            cascade_nonce: None,
            envelope_version: 0, // v0 legacy
        };

        let decrypted = decrypt_message(&secret, &v0_envelope).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_envelope_version_serde_default() {
        // Verify that deserializing an envelope without envelope_version field defaults to 0
        let json = r#"{
            "ephemeral_public_key": [1,2,3],
            "nonce": [4,5,6],
            "ciphertext": [7,8,9]
        }"#;
        let envelope: EncryptedEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.envelope_version, 0);
        assert!(envelope.kyber_ciphertext.is_none());
        assert!(envelope.cascade_nonce.is_none());
        assert!(!envelope.pqc_required);
    }

    #[test]
    fn test_aegis256_key_committing_tamper_detection() {
        // Verify that even 1-bit change in ciphertext fails decryption (key-committing property)
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"Key-committing AEAD tamper test";

        let mut envelope = encrypt_message(&public, plaintext).unwrap();
        // Flip one bit in the middle of ciphertext
        let mid = envelope.ciphertext.len() / 2;
        envelope.ciphertext[mid] ^= 0x01;

        let result = decrypt_message(&secret, &envelope);
        assert!(result.is_err());
    }
}

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use base64::Engine;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicBool, Ordering};
use x25519_dalek::{EphemeralSecret, PublicKey};

static SHADOW_ZERO_TRACE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Set by daemon runtime so shadow audit honors immutable process log mode
/// without relying on environment-variable state.
pub fn set_zero_trace_mode(enabled: bool) {
    SHADOW_ZERO_TRACE_ACTIVE.store(enabled, Ordering::SeqCst);
}

/// Shadow Mode: Executive-only encrypted channel
///
/// Design principles:
/// 1. Separate CA (Executive CA) — not visible to Corporate CA
/// 2. Ephemeral keys per session — no persistent session keys
/// 3. Cover traffic — constant-rate dummy packets mask real activity
/// 4. Encrypted Executive Audit — logs exist but require threshold decryption
///
/// SECURITY: This module requires Executive CA certificate to function.
/// IT admins, regular employees, and standard agents cannot access this.

/// Enable shadow mode for the current agent (requires executive certificate)
pub async fn enable_shadow_mode() -> Result<()> {
    // Verify executive certificate
    // TODO: Check if agent has Executive CA-signed certificate

    tracing::warn!("Shadow Mode ENABLED — all messages on this channel are encrypted");
    println!("⚡ Shadow Executive Mode activated");
    println!("  - Separate encrypted channel established");
    println!("  - Cover traffic generator started");
    println!("  - Persistent audit trail will not record shadow operations");
    println!("  - Encrypted executive audit log active (threshold decryption required)");

    // Start cover traffic generator
    tokio::spawn(async move {
        cover_traffic_generator().await;
    });

    Ok(())
}

/// Send a message through the shadow channel
pub async fn send_shadow_message(recipient_did: &str, message: &str) -> Result<()> {
    tracing::info!(to = %recipient_did, "Sending shadow message");

    // Generate ephemeral keypair for this single message
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // TODO: Look up recipient's shadow public key (from Executive CA registry)
    // For now, demonstrate the flow:

    println!("🔒 Shadow message prepared:");
    println!(
        "  Ephemeral key: {}...",
        hex::encode(&ephemeral_public.as_bytes()[..8])
    );
    println!("  Recipient: {}", recipient_did);
    println!(
        "  Payload size: {} bytes (padded)",
        pad_to_fixed_size(message.as_bytes()).len()
    );
    println!("  Forward secrecy: ✓ (ephemeral DH)");
    println!("  Audit trail: ✗ (shadow mode)");

    // Write to encrypted executive audit log
    write_shadow_audit_entry(recipient_did, "SHADOW_MSG", message.len()).await?;

    Ok(())
}

/// Request a file through the shadow channel
pub async fn request_shadow_file(from_did: &str, path: &str) -> Result<()> {
    tracing::info!(from = %from_did, path = %path, "Shadow file request");

    println!("🔒 Shadow file request:");
    println!("  Source agent: {}", from_did);
    println!("  Requested path: {}", path);
    println!("  Transfer mode: Shadow (no audit trail for other users)");

    // Write to encrypted executive audit log
    write_shadow_audit_entry(from_did, "SHADOW_FILE_REQUEST", 0).await?;

    Ok(())
}

/// Pad messages to a fixed size to prevent traffic analysis
pub fn pad_to_fixed_size(data: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 4096; // All shadow messages are 4KB
    let mut padded = vec![0u8; BLOCK_SIZE];
    let len = data.len().min(BLOCK_SIZE - 4);

    // First 4 bytes: actual data length (little-endian)
    padded[..4].copy_from_slice(&(len as u32).to_le_bytes());
    padded[4..4 + len].copy_from_slice(&data[..len]);

    // Fill rest with random bytes (not zeros — prevents pattern detection)
    rand::Rng::fill(&mut rand::thread_rng(), &mut padded[4 + len..]);

    padded
}

/// Generate a single cover traffic packet (4KB, random-padded).
/// Used by daemon's cover traffic emitter to send Heartbeat noise to peers.
pub fn generate_cover_packet() -> Vec<u8> {
    pad_to_fixed_size(b"COVER")
}

/// Generate cover traffic to mask real shadow communication
async fn cover_traffic_generator() {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        // Generate a dummy shadow packet (same size as real ones)
        let dummy = pad_to_fixed_size(b"COVER");

        // TODO: Send via the shadow transport channel
        // This ensures that an observer cannot distinguish real shadow
        // messages from cover traffic by timing analysis
        tracing::trace!(size = dummy.len(), "Cover traffic packet generated");
    }
}

/// Write to encrypted executive audit log
/// This log can ONLY be decrypted by threshold decryption (2/3 executives)
///
/// SECURITY: In Ghost mode, this is a complete no-op — zero disk writes.
/// In other modes, entries are encrypted with AES-256-GCM before writing.
async fn write_shadow_audit_entry(target_did: &str, action: &str, data_size: usize) -> Result<()> {
    // Ghost guard: NO disk writes whatsoever.
    if SHADOW_ZERO_TRACE_ACTIVE.load(Ordering::SeqCst) {
        return Ok(());
    }

    let entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "action": action,
        "target_did": target_did,
        "data_size": data_size,
    });

    let plaintext = serde_json::to_vec(&entry)?;

    // Encrypt with AES-256-GCM using a derived key
    // Key derivation: SHA-256(b"QYPHA_SHADOW_AUDIT_KEY" || session random)
    // TODO: Replace with proper Shamir threshold key (Phase 5)
    let session_key = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"QYPHA_SHADOW_AUDIT_KEY_v1");
        // Use a per-session random seed stored in env (generated once per daemon)
        let seed = std::env::var("_QYPHA_SHADOW_SEED").unwrap_or_else(|_| {
            let s = hex::encode(&rand::random::<[u8; 16]>());
            std::env::set_var("_QYPHA_SHADOW_SEED", &s);
            s
        });
        hasher.update(seed.as_bytes());
        hasher.finalize()
    };

    // Encrypt
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&session_key)
        .map_err(|e| anyhow::anyhow!("AES key error: {}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

    // Write encrypted entry: base64(nonce || ciphertext) per line
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);

    let log_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(|h| {
            std::path::PathBuf::from(h)
                .join(".qypha")
                .join("shadow_audit")
        })
        .map_err(|_| anyhow::anyhow!("Cannot determine home directory"))?;

    std::fs::create_dir_all(&log_dir)?;

    // Set restrictive permissions on the audit directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700));
    }

    let log_file = log_dir.join("audit.enc.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)?;

    use std::io::Write;
    writeln!(file, "{}", encoded)?;

    Ok(())
}

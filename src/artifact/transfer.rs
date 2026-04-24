use anyhow::Result;
use chrono::Utc;
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

use super::manifest::{ArtifactManifestLocal, FileEntryLocal};
use crate::crypto::identity::AgentKeyPair;
use crate::crypto::{encryption, signing};
use crate::network::protocol::{AgentRequest, FileTransferPayload, MessageKind};

/// File types that should travel as raw payloads instead of being wrapped in
/// another tar.gz layer. This avoids redundant compression for pre-compressed
/// archives and other formats that do not benefit from gzip.
const RAW_PAYLOAD_EXTENSIONS: &[&str] = &[
    "zip", "gz", "tgz", "bz2", "xz", "zst", "lz4", "lzma", "7z", "rar", "tar", "jpg", "jpeg",
    "png", "gif", "webp", "avif", "mp4", "mkv", "avi", "mov", "mp3", "aac", "flac", "ogg", "opus",
    "wma",
];

const COMPOUND_FILENAME_EXTENSIONS: &[&str] = &[
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tar.lz4",
    ".tar.lzma",
];

#[derive(Debug, Clone)]
pub struct ReceivedArtifact {
    pub manifest: ArtifactManifestLocal,
    pub final_path: std::path::PathBuf,
}

/// Validate untrusted artifact identifiers before using them in filesystem paths.
/// Allowed charset: ASCII alnum + '_' + '-'.
pub fn validate_artifact_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 {
        return Err(anyhow::anyhow!("Invalid artifact_id length"));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(anyhow::anyhow!(
            "Invalid artifact_id '{}': only [A-Za-z0-9_-] allowed",
            id
        ));
    }
    Ok(())
}

/// Build an encrypted, signed artifact and return a `FileTransferPayload`
/// ready to be sent over the P2P network to the recipient.
///
/// Encryption pipeline:
///   tar.gz(source) → AES-256-GCM(random_key) → wrap random_key with recipient X25519 ECDH
///   → Ed25519_sign(SHA-256(plaintext)) → FileTransferPayload
///
/// No one without the recipient's X25519 private key can read the data.
/// No one without our Ed25519 private key can forge the signature.
pub fn build_encrypted_transfer(
    keypair: &AgentKeyPair,
    recipient_x25519_public_key: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
    recipient_did: &str,
    path: &str,
    classification: &str,
) -> Result<FileTransferPayload> {
    build_encrypted_transfer_inner(
        keypair,
        recipient_x25519_public_key,
        recipient_kyber_public,
        recipient_did,
        path,
        classification,
        false,
    )
}

/// Build an encrypted transfer, optionally skipping local artifact store.
/// `zero_trace` = true in Ghost mode — no disk writes.
pub fn build_encrypted_transfer_zero_trace(
    keypair: &AgentKeyPair,
    recipient_x25519_public_key: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
    recipient_did: &str,
    path: &str,
    classification: &str,
) -> Result<FileTransferPayload> {
    build_encrypted_transfer_inner(
        keypair,
        recipient_x25519_public_key,
        recipient_kyber_public,
        recipient_did,
        path,
        classification,
        true,
    )
}

fn build_encrypted_transfer_inner(
    keypair: &AgentKeyPair,
    recipient_x25519_public_key: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
    recipient_did: &str,
    path: &str,
    classification: &str,
    zero_trace: bool,
) -> Result<FileTransferPayload> {
    let source = Path::new(path);
    if !source.exists() {
        return Err(anyhow::anyhow!("Path does not exist: {}", path));
    }

    // Step 1: Pack into transport payload. Pre-compressed single files travel
    // as raw payloads; directories and regular files are archived as tar.gz.
    let plaintext_data = pack_path(source)?;
    tracing::info!(
        size_bytes = plaintext_data.len(),
        "Packed source into transfer payload"
    );

    // Step 2: SHA-256 of plaintext (integrity proof, signed below)
    let plaintext_sha256 = hex::encode(Sha256::digest(&plaintext_data));

    // Step 3: Encrypt with hybrid PQC (Kyber + X25519). Classical fallback is disabled.
    let recipient_kyber_public = recipient_kyber_public.ok_or_else(|| {
        anyhow::anyhow!("SECURITY: recipient has no Kyber key — PQC-required transfer rejected")
    })?;
    let (key_envelope, mut encrypted_data) = encryption::hybrid_encrypt_artifact(
        recipient_x25519_public_key,
        Some(recipient_kyber_public),
        &plaintext_data,
    )?;
    tracing::info!(
        encrypted_bytes = encrypted_data.len(),
        "Artifact encrypted (hybrid PQC)"
    );

    // Step 4: Ed25519 sign the content hash so recipient can verify sender identity
    let signature = signing::sign_data(&keypair.signing_key, plaintext_sha256.as_bytes());

    // Step 5: Build manifest (local record)
    let artifact_id = format!("art_{}", Uuid::new_v4());
    let filename = source
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let manifest = ArtifactManifestLocal {
        artifact_id: artifact_id.clone(),
        sender_did: keypair.did.clone(),
        recipient_did: recipient_did.to_string(),
        created_at: Utc::now().timestamp() as u64,
        expires_at: Utc::now().timestamp() as u64 + 7200,
        files: collect_file_entries(source)?,
        total_size: plaintext_data.len() as u64,
        classification: classification.to_string(),
        sha256: plaintext_sha256.clone(),
        sender_signature: signature.clone(),
        sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
        merkle_root: None,
    };

    // Step 6: Save copy in local artifact store (skipped in Ghost mode)
    if !zero_trace {
        save_to_store(&manifest, &encrypted_data)?;
    }

    // Step 7: Serialize key_envelope for transport
    let key_envelope_bytes = serde_json::to_vec(&key_envelope)?;

    // Step 8: Pad encrypted_data to fixed-size bucket (traffic analysis resistance)
    // Without padding, observers can infer exact file size from encrypted payload size.
    // Bucket sizes: 64KB, 128KB, 256KB, 512KB, 1MB, 2MB, 4MB, 8MB, 10MB
    // (monolithic transfers are ≤10MB, chunked handles larger)
    let actual_encrypted_size = encrypted_data.len() as u64;
    let padded_size = pad_bucket_size(encrypted_data.len());
    if padded_size > encrypted_data.len() {
        let pad_len = padded_size - encrypted_data.len();
        let mut random_pad = vec![0u8; pad_len];
        rand::Rng::fill(&mut rand::thread_rng(), random_pad.as_mut_slice());
        encrypted_data.extend_from_slice(&random_pad);
    }

    Ok(FileTransferPayload {
        artifact_id,
        filename,
        classification: classification.to_string(),
        plaintext_sha256,
        encrypted_size: actual_encrypted_size, // actual size BEFORE padding
        key_envelope: key_envelope_bytes,
        encrypted_data, // padded with random bytes
        sender_signature: signature,
        sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
    })
}

/// Build an `AgentRequest` wrapping a `FileTransferPayload`
pub fn wrap_as_request(
    keypair: &AgentKeyPair,
    payload: FileTransferPayload,
) -> Result<AgentRequest> {
    let payload_bytes = bincode::serialize(&payload)
        .map_err(|e| anyhow::anyhow!("Failed to serialize transfer payload: {}", e))?;
    tracing::info!(
        json_would_be = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0),
        bincode_size = payload_bytes.len(),
        "Transfer payload serialized (bincode — no JSON bloat)"
    );
    let nonce = crate::crypto::next_request_nonce();
    // Sign canonical data: msg_type || payload || nonce || timestamp
    // Must match verification in daemon.rs message handler.
    let msg_type_bytes = serde_json::to_vec(&MessageKind::FileTransfer).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(msg_type_bytes.len() + payload_bytes.len() + 16);
    signed_data.extend_from_slice(&msg_type_bytes);
    signed_data.extend_from_slice(&payload_bytes);
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    let signature = signing::sign_data(&keypair.signing_key, &signed_data);

    Ok(AgentRequest {
        sender_did: keypair.did.clone(),
        sender_name: keypair.metadata.display_name.clone(),
        sender_role: keypair.metadata.role.clone(),
        msg_type: MessageKind::FileTransfer,
        payload: payload_bytes,
        signature,
        nonce,
        timestamp: nonce,
        message_id: uuid::Uuid::new_v4().to_string(),
        ttl_ms: 0,
    })
}

/// Receive and decrypt an incoming FileTransfer message.
///
/// Steps:
///   1. Deserialize FileTransferPayload from request payload
///   2. Verify Ed25519 signature using sender's verifying key
///   3. Decrypt: unwrap AES key with our X25519 secret → AES-GCM decrypt
///   4. Verify plaintext SHA-256
///   5. Safe unpack to output_dir
pub fn receive_encrypted_transfer(
    keypair: &AgentKeyPair,
    request_payload: &[u8],
    output_dir: &Path,
    expected_sender_vk: Option<[u8; 32]>,
) -> Result<ArtifactManifestLocal> {
    Ok(receive_encrypted_transfer_with_path(
        keypair,
        request_payload,
        output_dir,
        expected_sender_vk,
    )?
    .manifest)
}

pub fn receive_encrypted_transfer_with_path(
    keypair: &AgentKeyPair,
    request_payload: &[u8],
    output_dir: &Path,
    expected_sender_vk: Option<[u8; 32]>,
) -> Result<ReceivedArtifact> {
    // 1. Deserialize (bincode for efficient binary transport)
    let transfer: FileTransferPayload = bincode::deserialize(request_payload)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize transfer payload: {}", e))?;
    tracing::info!(
        payload_bytes = request_payload.len(),
        encrypted_data_bytes = transfer.encrypted_data.len(),
        "Transfer payload deserialized (bincode)"
    );

    // Validate untrusted artifact identifier before any filesystem use.
    validate_artifact_id(&transfer.artifact_id)?;

    // Ensure nested transfer identity cannot diverge from authenticated outer peer.
    if let Some(expected_vk) = expected_sender_vk {
        let expected_hex = hex::encode(expected_vk);
        if transfer.sender_verifying_key_hex != expected_hex {
            return Err(anyhow::anyhow!(
                "SECURITY: transfer payload sender key mismatch with authenticated peer"
            ));
        }
    }

    // 2. Verify Ed25519 signature
    let vk_bytes = hex::decode(&transfer.sender_verifying_key_hex)
        .map_err(|_| anyhow::anyhow!("Invalid sender verifying key hex"))?;
    let vk_bytes_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Verifying key wrong length"))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes_arr)
        .map_err(|e| anyhow::anyhow!("Invalid verifying key: {}", e))?;

    let signature = ed25519_dalek::Signature::from_slice(&transfer.sender_signature)
        .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;
    verifying_key
        .verify_strict(transfer.plaintext_sha256.as_bytes(), &signature)
        .map_err(|_| {
            anyhow::anyhow!("SECURITY: Signature verification FAILED — artifact may be forged!")
        })?;

    tracing::info!(artifact_id = %transfer.artifact_id, "Ed25519 signature verified ✓");

    // 3. Strip padding: encrypted_size tells us actual encrypted bytes (rest is random padding)
    let actual_size = transfer.encrypted_size as usize;
    let encrypted_data = if actual_size > 0 && actual_size < transfer.encrypted_data.len() {
        &transfer.encrypted_data[..actual_size]
    } else {
        &transfer.encrypted_data
    };

    // 4. Decrypt key envelope + data (hybrid PQC only; classical fallback disabled)
    let key_envelope: encryption::EncryptedEnvelope =
        serde_json::from_slice(&transfer.key_envelope)?;
    let secret_key_bytes = keypair.x25519_secret_key_bytes();
    if key_envelope.kyber_ciphertext.is_none() {
        return Err(anyhow::anyhow!(
            "SECURITY: transfer envelope missing Kyber ciphertext (PQC downgrade rejected)"
        ));
    }
    let kyber_secret = if !keypair.kyber_secret.is_empty() {
        Some(keypair.kyber_secret.as_slice())
    } else {
        None
    }
    .ok_or_else(|| {
        anyhow::anyhow!("SECURITY: receiver has no Kyber secret key — cannot decrypt PQC envelope")
    })?;
    let plaintext = encryption::hybrid_decrypt_artifact(
        &secret_key_bytes,
        Some(kyber_secret),
        &key_envelope,
        encrypted_data,
    )?;

    // 4. Verify plaintext hash
    let actual_sha256 = hex::encode(Sha256::digest(&plaintext));
    if actual_sha256 != transfer.plaintext_sha256 {
        return Err(anyhow::anyhow!(
            "INTEGRITY FAILURE: hash mismatch! expected={} got={}",
            transfer.plaintext_sha256,
            actual_sha256
        ));
    }
    tracing::info!("SHA-256 integrity check passed ✓");

    // 5. Materialize directly into receiver-designated directory.
    // Receiver controls output_dir (daemon scopes it by sender name).
    let final_path = materialize_plaintext_payload(&plaintext, &transfer.filename, output_dir)?;

    tracing::info!(
        artifact_id = %transfer.artifact_id,
        output = %final_path.display(),
        "Artifact decrypted and materialized ✓"
    );

    Ok(ReceivedArtifact {
        manifest: ArtifactManifestLocal {
            artifact_id: transfer.artifact_id,
            sender_did: "unknown".to_string(), // filled by caller from AgentRequest
            recipient_did: keypair.did.clone(),
            created_at: Utc::now().timestamp() as u64,
            expires_at: 0,
            files: vec![],
            total_size: plaintext.len() as u64,
            classification: transfer.classification,
            sha256: actual_sha256,
            sender_signature: transfer.sender_signature,
            sender_verifying_key_hex: transfer.sender_verifying_key_hex,
            merkle_root: None,
        },
        final_path,
    })
}

// ─── Legacy send_artifact (CLI `transfer` subcommand) ──────────────────────

/// Pack a file or folder and save an encrypted artifact locally
/// (CLI `transfer` subcommand — P2P send wired in daemon.rs)
pub async fn send_artifact(recipient_did: &str, path: &str, classification: &str) -> Result<()> {
    let source = Path::new(path);
    if !source.exists() {
        return Err(anyhow::anyhow!("Path does not exist: {}", path));
    }

    let packed_data = pack_path(source)?;
    let sha256 = hex::encode(Sha256::digest(&packed_data));

    let manifest = ArtifactManifestLocal {
        artifact_id: format!("art_{}", Uuid::new_v4()),
        sender_did: "self".to_string(),
        recipient_did: recipient_did.to_string(),
        created_at: Utc::now().timestamp() as u64,
        expires_at: Utc::now().timestamp() as u64 + 7200,
        files: collect_file_entries(source)?,
        total_size: packed_data.len() as u64,
        classification: classification.to_string(),
        sha256: sha256.clone(),
        sender_signature: vec![],
        sender_verifying_key_hex: String::new(),
        merkle_root: None,
    };

    save_to_store(&manifest, &packed_data)?;

    println!(
        "✓ Artifact {} created (use daemon REPL to send encrypted)",
        manifest.artifact_id
    );
    println!("  Files: {}", manifest.files.len());
    println!("  Size: {} bytes", manifest.total_size);
    println!("  SHA-256: {}", &sha256[..16]);

    Ok(())
}

// ─── Internal helpers ───────────────────────────────────────────────────────

pub(crate) fn should_use_raw_payload(source: &Path) -> bool {
    if !source.is_file() {
        return false;
    }
    source
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| RAW_PAYLOAD_EXTENSIONS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn is_gzip_payload(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

pub(crate) fn materialize_plaintext_payload(
    payload: &[u8],
    filename: &str,
    output_dir: &Path,
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    if is_gzip_payload(payload) {
        unpack_archive(payload, output_dir)
    } else {
        write_raw_payload(output_dir, filename, payload)
    }
}

pub(crate) fn materialize_payload_file(
    payload_path: &Path,
    filename: &str,
    output_dir: &Path,
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    if is_gzip_file(payload_path)? {
        unpack_archive_file_to_unique_root(payload_path, output_dir)
    } else {
        copy_raw_payload_to_unique_path(output_dir, filename, payload_path)
    }
}

fn write_raw_payload(
    output_dir: &Path,
    filename: &str,
    payload: &[u8],
) -> Result<std::path::PathBuf> {
    let safe_name = Path::new(filename)
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Invalid raw payload filename"))?;
    let output_path = reserve_unique_output_path(output_dir, safe_name)?;
    std::fs::write(&output_path, payload)?;
    Ok(output_path)
}

fn copy_raw_payload_to_unique_path(
    output_dir: &Path,
    filename: &str,
    payload_path: &Path,
) -> Result<std::path::PathBuf> {
    let safe_name = Path::new(filename)
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Invalid raw payload filename"))?;
    let output_path = reserve_unique_output_path(output_dir, safe_name)?;
    std::fs::copy(payload_path, &output_path)?;
    Ok(output_path)
}

pub(crate) fn archive_root_name(source: &Path) -> Result<std::path::PathBuf> {
    let name = source
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Invalid source path"))?;
    Ok(Path::new(name).to_path_buf())
}

/// Pack a file or directory into a transport payload.
pub fn pack_path(source: &Path) -> Result<Vec<u8>> {
    if should_use_raw_payload(source) {
        return std::fs::read(source).map_err(Into::into);
    }

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    let buf = Vec::new();
    let encoder = GzEncoder::new(buf, Compression::default());
    let mut archive = Builder::new(encoder);

    if source.is_dir() {
        let dir_name = archive_root_name(source)?;
        archive.append_dir_all(&dir_name, source)?;
    } else {
        let file_name = source
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
        archive.append_path_with_name(source, file_name)?;
    }

    let encoder = archive.into_inner()?;
    Ok(encoder.finish()?)
}

/// Public entry point for unpacking — used by chunked_transfer module.
pub fn unpack_archive_public(data: &[u8], output_dir: &Path) -> Result<()> {
    unpack_archive(data, output_dir).map(|_| ())
}

/// Public entry point for unpacking from an archive file (streaming from disk).
pub fn unpack_archive_file_public(archive_path: &Path, output_dir: &Path) -> Result<()> {
    unpack_archive_file_to_unique_root(archive_path, output_dir).map(|_| ())
}

fn unpack_archive_file_to_unique_root(
    archive_path: &Path,
    output_dir: &Path,
) -> Result<std::path::PathBuf> {
    use flate2::read::GzDecoder;
    use std::fs::File;
    use tar::Archive;

    std::fs::create_dir_all(output_dir)?;

    let file = File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.set_overwrite(false);
    unpack_archive_entries(&mut archive, output_dir)
}

/// Safely unpack archive to target directory (path traversal protection)
fn unpack_archive(data: &[u8], output_dir: &Path) -> Result<std::path::PathBuf> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    use tar::Archive;

    std::fs::create_dir_all(output_dir)?;

    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = Archive::new(decoder);
    archive.set_overwrite(false);
    unpack_archive_entries(&mut archive, output_dir)
}

fn unpack_archive_entries<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
) -> Result<std::path::PathBuf> {
    let staging_dir = create_unique_receive_staging_dir(output_dir)?;
    let unpack_result = (|| -> Result<std::path::PathBuf> {
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            let entry_type = entry.header().entry_type();

            // Reject link and special entries to prevent symlink/hardlink traversal.
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                return Err(anyhow::anyhow!(
                    "SECURITY: archive contains unsupported link entry: {:?}",
                    path
                ));
            }
            if !(entry_type.is_file() || entry_type.is_dir()) {
                return Err(anyhow::anyhow!(
                    "SECURITY: archive contains unsupported entry type at {:?}",
                    path
                ));
            }

            // SECURITY: Reject path traversal (zip-slip attack)
            if path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(anyhow::anyhow!(
                    "SECURITY: Path traversal detected: {:?}",
                    path
                ));
            }

            // Build full_path from canonical output_dir to avoid Windows UNC mismatch
            let canonical_output = staging_dir
                .canonicalize()
                .unwrap_or_else(|_| staging_dir.clone());
            let full_path = canonical_output.join(&path);

            // Ensure resolved path stays within output_dir
            if !full_path.starts_with(&canonical_output) {
                return Err(anyhow::anyhow!(
                    "SECURITY: Extracted path escapes sandbox: {:?}",
                    full_path
                ));
            }

            entry.unpack(&full_path)?;
        }

        let staged_root = resolve_staged_archive_root(&staging_dir)?;
        let final_path = move_staged_root_to_unique_destination(&staged_root, output_dir)?;
        let _ = std::fs::remove_dir(&staging_dir);
        Ok(final_path)
    })();
    if unpack_result.is_err() {
        let _ = std::fs::remove_dir_all(&staging_dir);
    }
    unpack_result
}

fn is_gzip_file(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 2];
    let n = file.read(&mut magic)?;
    Ok(n == 2 && magic == [0x1f, 0x8b])
}

fn create_unique_receive_staging_dir(output_dir: &Path) -> Result<std::path::PathBuf> {
    for _ in 0..32 {
        let candidate = output_dir.join(format!(".qlrx-{}", Uuid::new_v4().simple()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(anyhow::anyhow!(
        "Failed to allocate unique receive staging directory in {}",
        output_dir.display()
    ))
}

fn resolve_staged_archive_root(staging_dir: &Path) -> Result<std::path::PathBuf> {
    let mut entries = std::fs::read_dir(staging_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();
    match entries.len() {
        1 => Ok(entries.remove(0)),
        0 => Err(anyhow::anyhow!("Archive produced no files")),
        _ => Err(anyhow::anyhow!(
            "Archive contains multiple top-level entries; refusing ambiguous extraction"
        )),
    }
}

fn move_staged_root_to_unique_destination(
    staged_root: &Path,
    output_dir: &Path,
) -> Result<std::path::PathBuf> {
    let leaf_name = staged_root
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Archive root has invalid filename"))?;
    let final_path = reserve_unique_output_path(output_dir, leaf_name)?;
    std::fs::rename(staged_root, &final_path)?;
    Ok(final_path)
}

fn reserve_unique_output_path(
    output_dir: &Path,
    leaf_name: &std::ffi::OsStr,
) -> Result<std::path::PathBuf> {
    let initial = output_dir.join(leaf_name);
    if !initial.exists() {
        return Ok(initial);
    }

    let name = leaf_name.to_string_lossy();
    let (stem, ext) = split_name_for_collision_suffix(&name);
    for index in 2..10_000 {
        let candidate = output_dir.join(format_collision_name(&stem, &ext, index));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(anyhow::anyhow!(
        "Could not allocate unique destination for {} in {}",
        name,
        output_dir.display()
    ))
}

fn split_name_for_collision_suffix(name: &str) -> (String, String) {
    let lower = name.to_ascii_lowercase();
    for ext in COMPOUND_FILENAME_EXTENSIONS {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return (name[..name.len() - ext.len()].to_string(), ext.to_string());
        }
    }

    if let Some(stripped) = name.strip_prefix('.') {
        if !stripped.contains('.') {
            return (name.to_string(), String::new());
        }
    }

    let path = Path::new(name);
    let stem = path
        .file_stem()
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string());
    let ext = path
        .extension()
        .filter(|value| !value.is_empty())
        .map(|value| format!(".{}", value.to_string_lossy()))
        .unwrap_or_default();
    (stem, ext)
}

fn format_collision_name(stem: &str, ext: &str, index: usize) -> String {
    format!("{}-{}{}", stem, index, ext)
}

/// Collect file entries with per-file hashes for the manifest
fn collect_file_entries(source: &Path) -> Result<Vec<FileEntryLocal>> {
    let mut entries = Vec::new();

    if source.is_file() {
        let data = std::fs::read(source)?;
        entries.push(FileEntryLocal {
            path: source.file_name().unwrap().to_string_lossy().to_string(),
            size_bytes: data.len() as u64,
            sha256: hex::encode(Sha256::digest(&data)),
        });
    } else {
        for entry in walkdir::WalkDir::new(source)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let rel_path = entry.path().strip_prefix(source)?;
                let data = std::fs::read(entry.path())?;
                entries.push(FileEntryLocal {
                    path: rel_path.to_string_lossy().to_string(),
                    size_bytes: data.len() as u64,
                    sha256: hex::encode(Sha256::digest(&data)),
                });
            }
        }
    }

    Ok(entries)
}

/// Save encrypted blob + manifest to local artifact store
fn save_to_store(manifest: &ArtifactManifestLocal, data: &[u8]) -> Result<()> {
    let store_dir = artifact_store_dir()?;
    let artifact_path = store_dir.join(&manifest.artifact_id);
    std::fs::create_dir_all(&artifact_path)?;

    std::fs::write(artifact_path.join("data.enc"), data)?;
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    std::fs::write(artifact_path.join("manifest.json"), manifest_json)?;

    tracing::info!(
        artifact_id = %manifest.artifact_id,
        path = %artifact_path.display(),
        "Artifact stored in local store"
    );

    Ok(())
}

/// Default artifact store directory
fn artifact_store_dir() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("Cannot determine home directory"))?;
    let dir = Path::new(&home).join(".qypha").join("artifacts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Compute padded bucket size for traffic analysis resistance.
///
/// All monolithic file transfers (≤10MB) are padded to one of these fixed
/// bucket sizes so observers cannot deduce exact file size:
///   64KB, 128KB, 256KB, 512KB, 1MB, 2MB, 4MB, 8MB, 10MB
///
/// For example, a 300KB file → 512KB bucket, a 1.5MB file → 2MB bucket.
fn pad_bucket_size(actual_size: usize) -> usize {
    const BUCKETS: &[usize] = &[
        64 * 1024,        // 64 KB
        128 * 1024,       // 128 KB
        256 * 1024,       // 256 KB
        512 * 1024,       // 512 KB
        1024 * 1024,      // 1 MB
        2 * 1024 * 1024,  // 2 MB
        4 * 1024 * 1024,  // 4 MB
        8 * 1024 * 1024,  // 8 MB
        10 * 1024 * 1024, // 10 MB (monolithic transfer limit)
    ];

    for &bucket in BUCKETS {
        if actual_size <= bucket {
            return bucket;
        }
    }
    // Larger than 10MB — shouldn't happen for monolithic transfers,
    // but fall back to next 1MB boundary
    ((actual_size + 1024 * 1024 - 1) / (1024 * 1024)) * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_path_keeps_precompressed_file_raw() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("bundle.zip");
        let payload = b"PK\x03\x04already zipped".to_vec();
        std::fs::write(&archive_path, &payload).unwrap();

        let packed = pack_path(&archive_path).unwrap();

        assert_eq!(packed, payload);
    }

    #[test]
    fn receive_encrypted_transfer_writes_raw_payload_for_precompressed_file() {
        let sender = AgentKeyPair::generate("Sender", "finance");
        let receiver = AgentKeyPair::generate("Receiver", "finance");
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("payload.zip");
        let raw_payload = b"PK\x03\x04raw zip payload".to_vec();
        std::fs::write(&archive_path, &raw_payload).unwrap();

        let transfer = build_encrypted_transfer(
            &sender,
            &receiver.x25519_public_key_bytes(),
            Some(receiver.kyber_public.as_slice()),
            &receiver.did,
            archive_path.to_str().unwrap(),
            "confidential",
        )
        .unwrap();
        let encoded = bincode::serialize(&transfer).unwrap();
        let out = tempfile::tempdir().unwrap();

        let manifest = receive_encrypted_transfer(
            &receiver,
            &encoded,
            out.path(),
            Some(sender.verifying_key.to_bytes()),
        )
        .unwrap();

        let written = std::fs::read(out.path().join("payload.zip")).unwrap();
        assert_eq!(written, raw_payload);
        assert_eq!(manifest.total_size, raw_payload.len() as u64);
    }

    #[test]
    fn receive_encrypted_transfer_renames_raw_payload_on_collision() {
        let sender = AgentKeyPair::generate("Sender", "finance");
        let receiver = AgentKeyPair::generate("Receiver", "finance");
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("payload.zip");
        let raw_payload = b"PK\x03\x04raw zip payload".to_vec();
        std::fs::write(&archive_path, &raw_payload).unwrap();

        let transfer = build_encrypted_transfer(
            &sender,
            &receiver.x25519_public_key_bytes(),
            Some(receiver.kyber_public.as_slice()),
            &receiver.did,
            archive_path.to_str().unwrap(),
            "confidential",
        )
        .unwrap();
        let encoded = bincode::serialize(&transfer).unwrap();
        let out = tempfile::tempdir().unwrap();

        let first = receive_encrypted_transfer_with_path(
            &receiver,
            &encoded,
            out.path(),
            Some(sender.verifying_key.to_bytes()),
        )
        .unwrap();
        let second = receive_encrypted_transfer_with_path(
            &receiver,
            &encoded,
            out.path(),
            Some(sender.verifying_key.to_bytes()),
        )
        .unwrap();

        assert_eq!(first.final_path.file_name().unwrap(), "payload.zip");
        assert_eq!(second.final_path.file_name().unwrap(), "payload-2.zip");
        assert_eq!(std::fs::read(first.final_path).unwrap(), raw_payload);
        assert_eq!(std::fs::read(second.final_path).unwrap(), raw_payload);
    }

    #[test]
    fn pack_path_preserves_selected_directory_name() {
        let dir = tempfile::tempdir().unwrap();
        let folder_path = dir.path().join("selected-folder");
        let nested_dir = folder_path.join("docs");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(folder_path.join("root.txt"), b"root").unwrap();
        std::fs::write(nested_dir.join("nested.txt"), b"nested").unwrap();

        let packed = pack_path(&folder_path).unwrap();
        let out = tempfile::tempdir().unwrap();
        unpack_archive_public(&packed, out.path()).unwrap();

        assert_eq!(
            std::fs::read(out.path().join("selected-folder").join("root.txt")).unwrap(),
            b"root"
        );
        assert_eq!(
            std::fs::read(
                out.path()
                    .join("selected-folder")
                    .join("docs")
                    .join("nested.txt")
            )
            .unwrap(),
            b"nested"
        );
    }

    #[test]
    fn unpack_archive_public_renames_folder_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        let folder_path = dir.path().join("selected-folder");
        let nested_dir = folder_path.join("docs");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(folder_path.join("root.txt"), b"root").unwrap();
        std::fs::write(nested_dir.join("nested.txt"), b"nested").unwrap();

        let packed = pack_path(&folder_path).unwrap();
        let out = tempfile::tempdir().unwrap();
        unpack_archive_public(&packed, out.path()).unwrap();
        unpack_archive_public(&packed, out.path()).unwrap();

        assert!(out.path().join("selected-folder").exists());
        assert!(out.path().join("selected-folder-2").exists());
        assert_eq!(
            std::fs::read(out.path().join("selected-folder-2").join("root.txt")).unwrap(),
            b"root"
        );
    }

    #[test]
    fn unpack_archive_public_renames_single_file_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("report.pdf");
        std::fs::write(&file_path, b"pdf").unwrap();

        let packed = pack_path(&file_path).unwrap();
        let out = tempfile::tempdir().unwrap();
        unpack_archive_public(&packed, out.path()).unwrap();
        unpack_archive_public(&packed, out.path()).unwrap();

        assert_eq!(
            std::fs::read(out.path().join("report.pdf")).unwrap(),
            b"pdf"
        );
        assert_eq!(
            std::fs::read(out.path().join("report-2.pdf")).unwrap(),
            b"pdf"
        );
    }
}

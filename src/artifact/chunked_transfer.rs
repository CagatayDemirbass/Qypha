use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::crypto::identity::AgentKeyPair;
use crate::crypto::merkle::{MerkleProof, MerkleTree};
use crate::crypto::{encryption, signing};
use crate::network::protocol::{
    AgentRequest, ChunkDataPayload, ChunkTransferInitPayload, MessageKind, SealedInitPayload,
    SealedMetadata, TransferCompletePayload,
};

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const LARGE_FILE_THRESHOLD: usize = 10 * 1024 * 1024; // 10MB

/// Fixed-size padded block for traffic analysis resistance.
/// Every chunk on the wire is exactly this size, regardless of actual payload.
/// Observers cannot infer file size, chunk count, or transfer boundaries.
///
/// Set to DEFAULT_CHUNK_SIZE + 256KB to cover encryption overhead (IV, tag,
/// Kyber ciphertext, envelope JSON). All chunks — including the last partial
/// one — appear identical on the wire, but waste only ~6% bandwidth instead
/// of the 150% overhead that a 10MB pad would cause.
pub const PADDED_BLOCK_SIZE: usize = DEFAULT_CHUNK_SIZE + 256 * 1024; // 4.25MB
const PADDED_CHUNK_MARGIN_BYTES: usize = 256 * 1024;

/// Transfer session state — persisted for resumability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSession {
    pub session_id: String,
    #[serde(default)]
    pub resume_token: String,
    pub artifact_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    pub filename: String,
    pub classification: String,
    pub total_size: u64,
    pub chunk_size: usize,
    pub total_chunks: usize,
    pub merkle_root: [u8; 32],
    pub plaintext_sha256: String,
    pub chunks: Vec<ChunkState>,
    /// Chain hash linking this transfer to the transfer chain
    pub chain_hash: String,
    pub created_at: u64,
    pub status: TransferStatus,
}

/// Per-chunk tracking state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkState {
    pub index: usize,
    pub offset: u64,
    pub size: usize,
    pub sha256: [u8; 32],
    pub encrypted: bool,
    pub sent: bool,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransferStatus {
    Preparing,
    InProgress,
    Paused,
    Completed,
    Failed(String),
}

/// A single encrypted, signed chunk ready for transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    pub session_id: String,
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub encrypted_data: Vec<u8>,
    pub key_envelope: Vec<u8>,
    pub signature: Vec<u8>,
    pub merkle_proof: Vec<u8>,
    pub chunk_sha256: [u8; 32],
}

/// Prepare a chunked transfer session.
///
/// Splits the file data into chunks, builds a Merkle tree, and returns a session
/// ready for chunk-by-chunk encrypted transfer.
pub fn prepare_session(
    keypair: &AgentKeyPair,
    recipient_did: &str,
    filename: &str,
    classification: &str,
    data: &[u8],
    chunk_size: usize,
) -> Result<(TransferSession, Vec<Vec<u8>>)> {
    let artifact_id = format!("art_{}", uuid::Uuid::new_v4());
    let session_id = format!("sess_{}", uuid::Uuid::new_v4());
    let resume_token = uuid::Uuid::new_v4().simple().to_string();
    let plaintext_sha256 = hex::encode(Sha256::digest(data));

    // Split into chunks
    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
    let total_chunks = chunks.len();

    // Build Merkle tree
    let tree = MerkleTree::build(&chunks);

    // Build chunk states
    let mut chunk_states = Vec::with_capacity(total_chunks);
    let mut offset = 0u64;
    for (i, chunk) in chunks.iter().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(chunk);
        let hash: [u8; 32] = hasher.finalize().into();

        chunk_states.push(ChunkState {
            index: i,
            offset,
            size: chunk.len(),
            sha256: hash,
            encrypted: false,
            sent: false,
            acknowledged: false,
        });
        offset += chunk.len() as u64;
    }

    let session = TransferSession {
        session_id,
        resume_token,
        artifact_id,
        sender_did: keypair.did.clone(),
        recipient_did: recipient_did.to_string(),
        filename: filename.to_string(),
        classification: classification.to_string(),
        total_size: data.len() as u64,
        chunk_size,
        total_chunks,
        merkle_root: tree.root_hash,
        plaintext_sha256,
        chunks: chunk_states,
        chain_hash: String::new(),
        created_at: chrono::Utc::now().timestamp_millis() as u64,
        status: TransferStatus::Preparing,
    };

    // Store raw chunk data separately
    let chunk_data: Vec<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();

    Ok((session, chunk_data))
}

/// Streaming session preparation — writes packed data to a temp file and builds
/// session metadata without holding the entire file in memory twice.
///
/// Returns (session, temp_file_path). Chunks are read from the temp file
/// one at a time during `encrypt_chunk_from_file()`.
///
/// Memory usage: ~chunk_size (4 MB) at any time, regardless of file size.
pub fn prepare_session_streaming(
    keypair: &AgentKeyPair,
    recipient_did: &str,
    filename: &str,
    classification: &str,
    packed_data_path: &Path,
    chunk_size: usize,
) -> Result<TransferSession> {
    use std::io::Read;

    let file_size = std::fs::metadata(packed_data_path)?.len() as usize;
    let total_chunks = (file_size + chunk_size - 1) / chunk_size;

    let artifact_id = format!("art_{}", uuid::Uuid::new_v4());
    let session_id = format!("sess_{}", uuid::Uuid::new_v4());

    // Single pass: compute per-chunk SHA-256 hashes + total file SHA-256
    let mut file = std::fs::File::open(packed_data_path)?;
    let mut total_hasher = Sha256::new();
    let mut chunk_states = Vec::with_capacity(total_chunks);
    let mut chunk_hashes = Vec::with_capacity(total_chunks);
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;

    for i in 0..total_chunks {
        let bytes_read = {
            let mut total_read = 0;
            loop {
                let n = file.read(&mut buf[total_read..])?;
                if n == 0 {
                    break;
                }
                total_read += n;
                if total_read >= chunk_size {
                    break;
                }
            }
            total_read
        };
        let chunk_data = &buf[..bytes_read];

        // Chunk hash
        let hash: [u8; 32] = Sha256::digest(chunk_data).into();
        chunk_hashes.push(hash);

        // Total file hash (streaming)
        total_hasher.update(chunk_data);

        chunk_states.push(ChunkState {
            index: i,
            offset,
            size: bytes_read,
            sha256: hash,
            encrypted: false,
            sent: false,
            acknowledged: false,
        });
        offset += bytes_read as u64;
    }

    let plaintext_sha256 = hex::encode(total_hasher.finalize());

    // Build Merkle tree from chunk hashes (only hashes in memory, not data)
    let tree = MerkleTree::build_from_hashes(&chunk_hashes);

    let session = TransferSession {
        session_id,
        resume_token: uuid::Uuid::new_v4().simple().to_string(),
        artifact_id,
        sender_did: keypair.did.clone(),
        recipient_did: recipient_did.to_string(),
        filename: filename.to_string(),
        classification: classification.to_string(),
        total_size: file_size as u64,
        chunk_size,
        total_chunks,
        merkle_root: tree.root_hash,
        plaintext_sha256,
        chunks: chunk_states,
        chain_hash: String::new(),
        created_at: chrono::Utc::now().timestamp_millis() as u64,
        status: TransferStatus::Preparing,
    };

    Ok(session)
}

/// Read a single chunk from the packed data file for encryption.
///
/// Seeks to the correct offset and reads `chunk_size` bytes.
/// Memory usage: only one chunk at a time.
pub fn read_chunk_from_file(
    packed_data_path: &Path,
    session: &TransferSession,
    chunk_index: usize,
) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    if chunk_index >= session.total_chunks {
        return Err(anyhow::anyhow!("Chunk index {} out of range", chunk_index));
    }

    let chunk_state = &session.chunks[chunk_index];
    let mut file = std::fs::File::open(packed_data_path)?;
    file.seek(SeekFrom::Start(chunk_state.offset))?;

    let mut buf = vec![0u8; chunk_state.size];
    file.read_exact(&mut buf)?;

    Ok(buf)
}

fn runtime_temp_root() -> std::path::PathBuf {
    std::env::var("QYPHA_RUNTIME_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
}

/// Pack a file/directory to a temporary file (streaming, no memory bloat).
///
/// For single files with already-compressed extensions (.zip, .gz, .mp4, etc.),
/// the file is copied directly without tar+gzip overhead. Directories and
/// uncompressed files go through tar+gzip as before.
///
/// Returns the path to the temp file. Caller must clean up.

pub fn pack_to_temp_file(source: &Path) -> Result<std::path::PathBuf> {
    let temp_dir = runtime_temp_root().join("qypha-transfer");
    std::fs::create_dir_all(&temp_dir)?;

    // Set restrictive permissions on temp directory (owner-only: 0o700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700));
    }

    // Single file that's already packaged/compressed → raw copy (no tar+gzip)
    if super::transfer::should_use_raw_payload(source) {
        let temp_path = temp_dir.join(format!("raw_{}", uuid::Uuid::new_v4()));
        std::fs::copy(source, &temp_path)?;
        return Ok(temp_path);
    }

    // Directory or uncompressed file → tar+gzip
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    let temp_path = temp_dir.join(format!("pack_{}.tar.gz", uuid::Uuid::new_v4()));

    let file = std::fs::File::create(&temp_path)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = Builder::new(encoder);

    if source.is_dir() {
        let dir_name = super::transfer::archive_root_name(source)?;
        archive.append_dir_all(&dir_name, source)?;
    } else {
        let file_name = source
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
        archive.append_path_with_name(source, file_name)?;
    }

    let encoder = archive.into_inner()?;
    encoder.finish()?;

    Ok(temp_path)
}

/// Encrypt a single chunk for transmission.
///
/// Each chunk is independently encrypted with the recipient's X25519 key
/// and signed with the sender's Ed25519 key.
pub fn encrypt_chunk(
    session: &TransferSession,
    chunk_index: usize,
    chunk_data: &[u8],
    keypair: &AgentKeyPair,
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
) -> Result<EncryptedChunk> {
    if chunk_index >= session.total_chunks {
        return Err(anyhow::anyhow!("Chunk index {} out of range", chunk_index));
    }

    // Encrypt chunk with hybrid PQC (Kyber + X25519). Classical fallback is disabled.
    let recipient_kyber_public = recipient_kyber_public.ok_or_else(|| {
        anyhow::anyhow!("SECURITY: recipient has no Kyber key — chunk transfer requires PQC")
    })?;
    let (key_envelope, encrypted_data) = encryption::hybrid_encrypt_artifact(
        recipient_x25519_public,
        Some(recipient_kyber_public),
        chunk_data,
    )?;
    let key_envelope_bytes = serde_json::to_vec(&key_envelope)?;

    // Sign the chunk hash
    let chunk_hash = session.chunks[chunk_index].sha256;
    let signature = signing::sign_data(&keypair.signing_key, &chunk_hash);

    // Generate Merkle proof for this chunk
    let _chunks_as_refs: Vec<&[u8]> = vec![]; // We use pre-computed hashes
    let tree =
        MerkleTree::build_from_hashes(&session.chunks.iter().map(|c| c.sha256).collect::<Vec<_>>());
    let proof = tree.generate_proof(chunk_index);
    let merkle_proof_bytes = serde_json::to_vec(&proof)?;

    Ok(EncryptedChunk {
        session_id: session.session_id.clone(),
        chunk_index,
        total_chunks: session.total_chunks,
        encrypted_data,
        key_envelope: key_envelope_bytes,
        signature,
        merkle_proof: merkle_proof_bytes,
        chunk_sha256: chunk_hash,
    })
}

/// Precompute serialized Merkle proofs for every chunk in a session.
///
/// This keeps receiver-side verification identical while avoiding per-chunk
/// Merkle tree rebuilds in sender hot paths.
pub fn build_serialized_merkle_proof_cache(session: &TransferSession) -> Result<Vec<Vec<u8>>> {
    if session.chunks.is_empty() {
        return Err(anyhow::anyhow!(
            "Cannot build Merkle proof cache for empty transfer session"
        ));
    }

    let chunk_hashes: Vec<[u8; 32]> = session.chunks.iter().map(|chunk| chunk.sha256).collect();
    let tree = MerkleTree::build_from_hashes(&chunk_hashes);
    if tree.root_hash != session.merkle_root {
        return Err(anyhow::anyhow!(
            "Transfer session Merkle root does not match computed chunk hash tree"
        ));
    }

    tree.generate_all_proofs()
        .into_iter()
        .map(|proof| serde_json::to_vec(&proof).map_err(anyhow::Error::from))
        .collect()
}

pub fn padded_block_size_for_chunk_size(chunk_size: usize) -> usize {
    chunk_size.saturating_add(PADDED_CHUNK_MARGIN_BYTES)
}

fn encrypt_chunk_with_serialized_proof(
    session: &TransferSession,
    chunk_index: usize,
    serialized_merkle_proof: &[u8],
    chunk_data: &[u8],
    keypair: &AgentKeyPair,
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
) -> Result<EncryptedChunk> {
    if chunk_index >= session.total_chunks {
        return Err(anyhow::anyhow!("Chunk index {} out of range", chunk_index));
    }

    let recipient_kyber_public = recipient_kyber_public.ok_or_else(|| {
        anyhow::anyhow!("SECURITY: recipient has no Kyber key — chunk transfer requires PQC")
    })?;
    let (key_envelope, encrypted_data) = encryption::hybrid_encrypt_artifact(
        recipient_x25519_public,
        Some(recipient_kyber_public),
        chunk_data,
    )?;
    let key_envelope_bytes = serde_json::to_vec(&key_envelope)?;

    let chunk_hash = session.chunks[chunk_index].sha256;
    let signature = signing::sign_data(&keypair.signing_key, &chunk_hash);

    Ok(EncryptedChunk {
        session_id: session.session_id.clone(),
        chunk_index,
        total_chunks: session.total_chunks,
        encrypted_data,
        key_envelope: key_envelope_bytes,
        signature,
        merkle_proof: serialized_merkle_proof.to_vec(),
        chunk_sha256: chunk_hash,
    })
}

/// Encrypt a chunk and pad to PADDED_BLOCK_SIZE (currently 4.25 MB)
/// for traffic analysis resistance.
///
/// The encrypted chunk is padded with random bytes to a fixed size, making all chunks
/// indistinguishable on the wire. Observers cannot infer actual data size.
/// Returns (padded_data, actual_encrypted_size) — receiver strips padding using the size.
pub fn encrypt_chunk_padded(
    session: &TransferSession,
    chunk_index: usize,
    chunk_data: &[u8],
    keypair: &AgentKeyPair,
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
) -> Result<(EncryptedChunk, Vec<u8>, usize)> {
    let encrypted = encrypt_chunk(
        session,
        chunk_index,
        chunk_data,
        keypair,
        recipient_x25519_public,
        recipient_kyber_public,
    )?;

    let actual_size = encrypted.encrypted_data.len();

    // Pad encrypted_data to fixed PADDED_BLOCK_SIZE with random bytes
    let mut padded = encrypted.encrypted_data.clone();
    if padded.len() < PADDED_BLOCK_SIZE {
        let pad_len = PADDED_BLOCK_SIZE - padded.len();
        let mut random_pad = vec![0u8; pad_len];
        rand::Rng::fill(&mut rand::thread_rng(), random_pad.as_mut_slice());
        padded.extend_from_slice(&random_pad);
    }

    Ok((encrypted, padded, actual_size))
}

/// Encrypt a chunk using a pre-serialized Merkle proof cache and pad based on the
/// active chunk size. Used by direct iroh transfers to avoid per-chunk Merkle
/// tree rebuilds without changing receiver verification semantics.
pub fn encrypt_chunk_padded_with_serialized_proof(
    session: &TransferSession,
    chunk_index: usize,
    serialized_merkle_proof: &[u8],
    chunk_data: &[u8],
    keypair: &AgentKeyPair,
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
) -> Result<(EncryptedChunk, Vec<u8>, usize)> {
    let encrypted = encrypt_chunk_with_serialized_proof(
        session,
        chunk_index,
        serialized_merkle_proof,
        chunk_data,
        keypair,
        recipient_x25519_public,
        recipient_kyber_public,
    )?;

    let actual_size = encrypted.encrypted_data.len();
    let padded_block_size = padded_block_size_for_chunk_size(session.chunk_size);
    let mut padded = encrypted.encrypted_data.clone();
    if padded.len() < padded_block_size {
        let pad_len = padded_block_size - padded.len();
        let mut random_pad = vec![0u8; pad_len];
        rand::Rng::fill(&mut rand::thread_rng(), random_pad.as_mut_slice());
        padded.extend_from_slice(&random_pad);
    }

    Ok((encrypted, padded, actual_size))
}

/// Strip padding from a padded chunk, returning only the actual encrypted data.
pub fn strip_padding(padded_data: &[u8], actual_encrypted_size: usize) -> &[u8] {
    if actual_encrypted_size > 0 && actual_encrypted_size <= padded_data.len() {
        &padded_data[..actual_encrypted_size]
    } else {
        padded_data
    }
}

/// Receive and verify a single encrypted chunk.
///
/// Steps:
///   1. Verify Merkle proof (chunk belongs to the tree)
///   2. Decrypt chunk data
///   3. Verify SHA-256 of decrypted data matches the claimed hash
///   4. Verify Ed25519 signature
pub fn receive_chunk(
    keypair: &AgentKeyPair,
    encrypted_chunk: &EncryptedChunk,
    expected_merkle_root: &[u8; 32],
    sender_verifying_key_hex: &str,
) -> Result<Vec<u8>> {
    // 1. Verify Merkle proof
    let proof: MerkleProof = serde_json::from_slice(&encrypted_chunk.merkle_proof)?;
    if proof.root_hash != *expected_merkle_root {
        return Err(anyhow::anyhow!(
            "SECURITY: Merkle root mismatch for chunk {} — possible tampering!",
            encrypted_chunk.chunk_index
        ));
    }
    if !proof.verify_hash() {
        return Err(anyhow::anyhow!(
            "SECURITY: Merkle proof invalid for chunk {} — data tampered!",
            encrypted_chunk.chunk_index
        ));
    }

    // 2. Decrypt chunk (hybrid PQC only; classical fallback disabled)
    let key_envelope: encryption::EncryptedEnvelope =
        serde_json::from_slice(&encrypted_chunk.key_envelope)?;
    if key_envelope.kyber_ciphertext.is_none() {
        return Err(anyhow::anyhow!(
            "SECURITY: chunk envelope missing Kyber ciphertext (PQC downgrade rejected)"
        ));
    }
    let secret_key = keypair.x25519_secret_key_bytes();
    let kyber_secret = if !keypair.kyber_secret.is_empty() {
        Some(keypair.kyber_secret.as_slice())
    } else {
        None
    }
    .ok_or_else(|| {
        anyhow::anyhow!("SECURITY: receiver has no Kyber secret key — cannot decrypt chunk")
    })?;
    let decrypted = encryption::hybrid_decrypt_artifact(
        &secret_key,
        Some(kyber_secret),
        &key_envelope,
        &encrypted_chunk.encrypted_data,
    )?;

    // 3. Verify SHA-256
    let actual_hash: [u8; 32] = Sha256::digest(&decrypted).into();
    if actual_hash != encrypted_chunk.chunk_sha256 {
        return Err(anyhow::anyhow!(
            "INTEGRITY FAILURE: chunk {} hash mismatch!",
            encrypted_chunk.chunk_index
        ));
    }

    // 4. Verify Ed25519 signature
    let vk_bytes = hex::decode(sender_verifying_key_hex)
        .map_err(|_| anyhow::anyhow!("Invalid sender verifying key hex"))?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Verifying key wrong length"))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| anyhow::anyhow!("Invalid verifying key: {}", e))?;

    let valid = signing::verify_signature(
        &verifying_key,
        &encrypted_chunk.chunk_sha256,
        &encrypted_chunk.signature,
    )?;
    if !valid {
        return Err(anyhow::anyhow!(
            "SECURITY: Signature verification FAILED for chunk {}!",
            encrypted_chunk.chunk_index
        ));
    }

    Ok(decrypted)
}

/// Reassemble all received chunks into the original data and verify the Merkle root.
pub fn reassemble_and_verify(
    chunks: &[Vec<u8>],
    expected_merkle_root: &[u8; 32],
    expected_sha256: &str,
) -> Result<Vec<u8>> {
    // Build Merkle tree from received chunks
    let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    if !MerkleTree::verify_root(&refs, expected_merkle_root) {
        return Err(anyhow::anyhow!(
            "SECURITY: Merkle root verification FAILED — data tampered during transfer!"
        ));
    }

    // Reassemble
    let mut data = Vec::new();
    for chunk in chunks {
        data.extend_from_slice(chunk);
    }

    // Verify total SHA-256
    let actual_sha256 = hex::encode(Sha256::digest(&data));
    if actual_sha256 != expected_sha256 {
        return Err(anyhow::anyhow!(
            "INTEGRITY FAILURE: reassembled data hash mismatch! expected={} got={}",
            expected_sha256,
            actual_sha256
        ));
    }

    Ok(data)
}

// ─── Protocol payload builders ──────────────────────────────────────────────

/// Build the `ChunkTransferInit` protocol payload from a prepared session.
pub fn build_init_payload(
    session: &TransferSession,
    keypair: &AgentKeyPair,
) -> ChunkTransferInitPayload {
    ChunkTransferInitPayload {
        session_id: session.session_id.clone(),
        artifact_id: session.artifact_id.clone(),
        filename: session.filename.clone(),
        classification: session.classification.clone(),
        total_size: session.total_size,
        chunk_size: session.chunk_size,
        total_chunks: session.total_chunks,
        merkle_root: session.merkle_root,
        plaintext_sha256: session.plaintext_sha256.clone(),
        sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
        version: 1,
        requires_reapproval: false,
        resume_requested: false,
        resume_token: session.resume_token.clone(),
    }
}

/// Build a sealed init payload — hides sensitive metadata from observers.
///
/// Version 2: Only sends session_id, total_chunks, merkle_root.
/// All sensitive metadata (filename, classification, size) is encrypted
/// and attached to chunk[0] as sealed_metadata blob.
pub fn build_sealed_init_payload(
    session: &TransferSession,
    keypair: &AgentKeyPair,
) -> (ChunkTransferInitPayload, SealedMetadata) {
    let sealed_meta = SealedMetadata {
        artifact_id: session.artifact_id.clone(),
        filename: session.filename.clone(),
        classification: session.classification.clone(),
        total_size: session.total_size,
        chunk_size: session.chunk_size,
        plaintext_sha256: session.plaintext_sha256.clone(),
    };

    // Init payload with dummy values for sensitive fields
    let init = ChunkTransferInitPayload {
        session_id: session.session_id.clone(),
        artifact_id: String::new(),    // hidden
        filename: String::new(),       // hidden
        classification: String::new(), // hidden
        total_size: 0,                 // hidden
        chunk_size: 0,                 // hidden
        total_chunks: session.total_chunks,
        merkle_root: session.merkle_root,
        plaintext_sha256: String::new(), // hidden
        sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
        version: 2,
        requires_reapproval: false,
        resume_requested: false,
        resume_token: session.resume_token.clone(),
    };

    (init, sealed_meta)
}

/// Encrypt the sealed metadata blob for inclusion in chunk[0].
pub fn encrypt_sealed_metadata(
    metadata: &SealedMetadata,
    recipient_x25519_public: &[u8; 32],
    recipient_kyber_public: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let recipient_kyber_public = recipient_kyber_public.ok_or_else(|| {
        anyhow::anyhow!("SECURITY: recipient has no Kyber key — cannot seal metadata")
    })?;
    let meta_bytes = serde_json::to_vec(metadata)?;
    let (envelope, encrypted) = encryption::hybrid_encrypt_artifact(
        recipient_x25519_public,
        Some(recipient_kyber_public),
        &meta_bytes,
    )?;
    let envelope_bytes = serde_json::to_vec(&envelope)?;
    Ok((encrypted, envelope_bytes))
}

/// Decrypt sealed metadata from chunk[0].
pub fn decrypt_sealed_metadata(
    sealed_data: &[u8],
    key_envelope_bytes: &[u8],
    keypair: &AgentKeyPair,
) -> Result<SealedMetadata> {
    let envelope: encryption::EncryptedEnvelope = serde_json::from_slice(key_envelope_bytes)?;
    if envelope.kyber_ciphertext.is_none() {
        return Err(anyhow::anyhow!(
            "SECURITY: sealed metadata envelope missing Kyber ciphertext (PQC downgrade rejected)"
        ));
    }
    let secret_key = keypair.x25519_secret_key_bytes();
    let kyber_secret = if !keypair.kyber_secret.is_empty() {
        Some(keypair.kyber_secret.as_slice())
    } else {
        None
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "SECURITY: receiver has no Kyber secret key — cannot decrypt sealed metadata"
        )
    })?;
    let decrypted = encryption::hybrid_decrypt_artifact(
        &secret_key,
        Some(kyber_secret),
        &envelope,
        sealed_data,
    )?;
    let metadata: SealedMetadata = serde_json::from_slice(&decrypted)?;
    Ok(metadata)
}

/// Build a `ChunkData` protocol payload from an encrypted chunk.
pub fn build_chunk_payload(chunk: &EncryptedChunk) -> ChunkDataPayload {
    ChunkDataPayload {
        session_id: chunk.session_id.clone(),
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        encrypted_data: chunk.encrypted_data.clone(),
        key_envelope: chunk.key_envelope.clone(),
        signature: chunk.signature.clone(),
        merkle_proof: chunk.merkle_proof.clone(),
        chunk_sha256: chunk.chunk_sha256,
        actual_encrypted_size: 0,
        sealed_metadata: None,
        sealed_metadata_key_envelope: None,
    }
}

/// Build a padded `ChunkData` protocol payload — fixed 10MB on the wire.
pub fn build_chunk_payload_padded(
    chunk: &EncryptedChunk,
    padded_data: Vec<u8>,
    actual_encrypted_size: usize,
) -> ChunkDataPayload {
    ChunkDataPayload {
        session_id: chunk.session_id.clone(),
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        encrypted_data: padded_data,
        key_envelope: chunk.key_envelope.clone(),
        signature: chunk.signature.clone(),
        merkle_proof: chunk.merkle_proof.clone(),
        chunk_sha256: chunk.chunk_sha256,
        actual_encrypted_size,
        sealed_metadata: None,
        sealed_metadata_key_envelope: None,
    }
}

/// Build a `TransferComplete` protocol payload.
pub fn build_complete_payload(session: &TransferSession) -> TransferCompletePayload {
    TransferCompletePayload {
        session_id: session.session_id.clone(),
        artifact_id: session.artifact_id.clone(),
        total_chunks: session.total_chunks,
        merkle_root: session.merkle_root,
    }
}

/// Wrap a serializable payload into an `AgentRequest` with proper signing.
pub fn wrap_chunk_request(
    keypair: &AgentKeyPair,
    msg_type: MessageKind,
    payload_bytes: Vec<u8>,
    ttl_ms: u64,
) -> Result<AgentRequest> {
    let nonce = crate::crypto::next_request_nonce();

    // Sign canonical data: msg_type || payload || nonce || timestamp
    // Must match verification in daemon.rs message handler.
    let msg_type_bytes = serde_json::to_vec(&msg_type).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(msg_type_bytes.len() + payload_bytes.len() + 16);
    signed_data.extend_from_slice(&msg_type_bytes);
    signed_data.extend_from_slice(&payload_bytes);
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    signed_data.extend_from_slice(&nonce.to_le_bytes()); // timestamp == nonce
    let signature = signing::sign_data(&keypair.signing_key, &signed_data);

    Ok(AgentRequest {
        sender_did: keypair.did.clone(),
        sender_name: keypair.metadata.display_name.clone(),
        sender_role: keypair.metadata.role.clone(),
        msg_type,
        payload: payload_bytes,
        signature,
        nonce,
        timestamp: nonce,
        message_id: uuid::Uuid::new_v4().to_string(),
        ttl_ms,
    })
}

// ─── Receive session tracking ──────────────────────────────────────────────

/// State for tracking an incoming chunked transfer on the receiver side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkedReceiveSession {
    pub init: ChunkTransferInitPayload,
    pub sender_did: String,
    pub sender_name: String,
    /// Per-session private temp directory for decrypted chunk staging.
    /// Contains only chunk payload bytes with index-based filenames.
    pub temp_dir: PathBuf,
    /// Received chunk indices for duplicate detection and completeness checks.
    pub received_indices: HashSet<usize>,
    pub received_count: usize,
    pub created_at: u64,
    /// Timestamp of last chunk activity (receive or init). Used for stale detection.
    pub last_chunk_at: u64,
    /// Whether the TransferComplete message has been received (may arrive before all chunks over Tor).
    pub transfer_complete_received: bool,
}

impl ChunkedReceiveSession {
    /// Create a new receive session from an init payload.
    pub fn new(
        init: ChunkTransferInitPayload,
        sender_did: String,
        sender_name: String,
    ) -> Result<Self> {
        Self::new_in_root(
            init,
            sender_did,
            sender_name,
            &runtime_temp_root().join("qypha-chunk-recv"),
        )
    }

    pub fn new_in_root(
        init: ChunkTransferInitPayload,
        sender_did: String,
        sender_name: String,
        root: &Path,
    ) -> Result<Self> {
        if init.total_chunks == 0 {
            return Err(anyhow::anyhow!(
                "SECURITY: Transfer rejected — total_chunks=0 is invalid."
            ));
        }
        let temp_dir = root.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&temp_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700));
            if let Some(parent) = temp_dir.parent() {
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let now = chrono::Utc::now().timestamp_millis() as u64;
        Ok(Self {
            init,
            sender_did,
            sender_name,
            temp_dir,
            received_indices: HashSet::new(),
            received_count: 0,
            created_at: now,
            last_chunk_at: now,
            transfer_complete_received: false,
        })
    }

    fn chunk_file_path(&self, index: usize) -> PathBuf {
        self.temp_dir.join(format!("{:08}.chunk", index))
    }

    pub fn received_indices_sorted(&self) -> Vec<usize> {
        let mut indices = self.received_indices.iter().copied().collect::<Vec<_>>();
        indices.sort_unstable();
        indices
    }

    pub fn can_auto_resume(&self, init: &ChunkTransferInitPayload, sender_did: &str) -> bool {
        init.resume_requested
            && !init.resume_token.trim().is_empty()
            && self.sender_did == sender_did
            && self.init.session_id == init.session_id
            && self.init.resume_token == init.resume_token
            && self.init.total_chunks == init.total_chunks
            && self.init.merkle_root == init.merkle_root
            && self.init.sender_verifying_key_hex == init.sender_verifying_key_hex
    }

    /// Store a decrypted chunk to disk. Returns true if this was a new chunk (not duplicate).
    pub fn store_chunk(&mut self, index: usize, data: Vec<u8>) -> Result<bool> {
        use std::io::Write;

        if index >= self.init.total_chunks {
            return Ok(false);
        }
        if self.received_indices.contains(&index) {
            return Ok(false); // duplicate
        }

        let chunk_path = self.chunk_file_path(index);
        let mut file = match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&chunk_path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(anyhow::anyhow!("Failed to open chunk file: {}", e)),
        };
        file.write_all(&data)?;

        self.received_indices.insert(index);
        self.received_count += 1;
        self.last_chunk_at = chrono::Utc::now().timestamp_millis() as u64;
        Ok(true)
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.received_count == self.init.total_chunks
    }

    /// Apply decrypted sealed metadata to a version-2 session.
    /// Populates the dummy fields in init with real values from the encrypted blob.
    pub fn apply_sealed_metadata(&mut self, meta: SealedMetadata) {
        self.init.artifact_id = meta.artifact_id;
        self.init.filename = meta.filename;
        self.init.classification = meta.classification;
        self.init.total_size = meta.total_size;
        self.init.chunk_size = meta.chunk_size;
        self.init.plaintext_sha256 = meta.plaintext_sha256;
    }

    /// Finalize: reassemble all chunks, verify Merkle root + SHA-256, unpack archive.
    pub fn finalize(self, output_dir: &Path) -> Result<super::manifest::ArtifactManifestLocal> {
        Ok(self.finalize_with_path(output_dir)?.0)
    }

    /// Finalize without consuming the receive session, so callers can retry on failure.
    pub fn finalize_ref(
        &self,
        output_dir: &Path,
    ) -> Result<super::manifest::ArtifactManifestLocal> {
        Ok(self.finalize_ref_with_path(output_dir)?.0)
    }

    pub fn finalize_with_path(
        self,
        output_dir: &Path,
    ) -> Result<(super::manifest::ArtifactManifestLocal, std::path::PathBuf)> {
        let temp_dir = self.temp_dir.clone();
        let result = self.finalize_ref_with_path(output_dir);
        if result.is_ok() {
            let _ = std::fs::remove_dir_all(&temp_dir);
        }
        result
    }

    pub fn finalize_ref_with_path(
        &self,
        output_dir: &Path,
    ) -> Result<(super::manifest::ArtifactManifestLocal, std::path::PathBuf)> {
        use sha2::Digest;
        use std::io::{Read, Write};

        if !self.is_complete() {
            return Err(anyhow::anyhow!(
                "Cannot finalize: only {}/{} chunks received",
                self.received_count,
                self.init.total_chunks
            ));
        }

        // Reconstruct archive on disk in strict chunk order while streaming SHA-256.
        let assembled_path = self
            .temp_dir
            .join(format!("{}.assembled", uuid::Uuid::new_v4()));
        let mut assembled = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&assembled_path)?;
        let mut hasher = Sha256::new();
        let mut total_size: u64 = 0;

        for idx in 0..self.init.total_chunks {
            let chunk_path = self.chunk_file_path(idx);
            if !chunk_path.exists() {
                return Err(anyhow::anyhow!("Missing chunk {} during finalize", idx));
            }

            let mut chunk_file = std::fs::File::open(&chunk_path)?;
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = chunk_file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                assembled.write_all(&buf[..n])?;
                total_size = total_size.saturating_add(n as u64);
            }
        }
        assembled.flush()?;

        // Verify full payload SHA-256 after reassembly.
        let actual_sha256 = hex::encode(hasher.finalize());
        if actual_sha256 != self.init.plaintext_sha256 {
            return Err(anyhow::anyhow!(
                "INTEGRITY FAILURE: reassembled data hash mismatch! expected={} got={}",
                self.init.plaintext_sha256,
                actual_sha256
            ));
        }

        // Materialize into receiver-designated directory using the same
        // unique-naming policy as direct transfers.
        super::transfer::validate_artifact_id(&self.init.artifact_id)?;
        let final_path = super::transfer::materialize_payload_file(
            &assembled_path,
            &self.init.filename,
            output_dir,
        )?;

        Ok((
            super::manifest::ArtifactManifestLocal {
                artifact_id: self.init.artifact_id.clone(),
                sender_did: self.sender_did.clone(),
                recipient_did: String::new(), // filled by caller
                created_at: chrono::Utc::now().timestamp() as u64,
                expires_at: 0,
                files: vec![],
                total_size,
                classification: self.init.classification.clone(),
                sha256: self.init.plaintext_sha256.clone(),
                sender_signature: vec![],
                sender_verifying_key_hex: self.init.sender_verifying_key_hex.clone(),
                merkle_root: Some(hex::encode(self.init.merkle_root)),
            },
            final_path,
        ))
    }
}

impl Drop for ChunkedReceiveSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

/// Save a transfer session to disk for resumability
pub fn save_session(session: &TransferSession, dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.session.json", session.session_id));
    let json = serde_json::to_string_pretty(session)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Load a transfer session from disk
pub fn load_session(session_id: &str, dir: &Path) -> Result<TransferSession> {
    let path = dir.join(format!("{}.session.json", session_id));
    let content = std::fs::read_to_string(&path)?;
    let session: TransferSession = serde_json::from_str(&content)?;
    Ok(session)
}

/// Get indices of chunks that still need to be sent (for resume)
pub fn pending_chunk_indices(session: &TransferSession) -> Vec<usize> {
    session
        .chunks
        .iter()
        .filter(|c| !c.acknowledged)
        .map(|c| c.index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::AgentKeyPair;

    fn setup_keypairs() -> (AgentKeyPair, AgentKeyPair) {
        let sender = AgentKeyPair::generate("Sender", "finance");
        let receiver = AgentKeyPair::generate("Receiver", "data_scientist");
        (sender, receiver)
    }

    #[test]
    fn test_prepare_session() {
        let (sender, _) = setup_keypairs();
        let data = vec![0u8; 12 * 1024 * 1024]; // 12MB
        let (session, chunks) = prepare_session(
            &sender,
            "did:nxf:recv",
            "test.csv",
            "confidential",
            &data,
            DEFAULT_CHUNK_SIZE,
        )
        .unwrap();

        assert_eq!(session.total_chunks, 3); // 12MB / 4MB = 3
        assert_eq!(chunks.len(), 3);
        assert_eq!(session.total_size, 12 * 1024 * 1024);
    }

    #[test]
    fn test_encrypt_and_receive_chunk() {
        let (sender, receiver) = setup_keypairs();
        let data = b"Hello, this is a test chunk of data for encryption!";

        let (session, chunk_data) =
            prepare_session(&sender, &receiver.did, "test.txt", "internal", data, 1024).unwrap();

        let encrypted = encrypt_chunk(
            &session,
            0,
            &chunk_data[0],
            &sender,
            &receiver.x25519_public_key_bytes(),
            Some(receiver.kyber_public.as_slice()),
        )
        .unwrap();

        let decrypted = receive_chunk(
            &receiver,
            &encrypted,
            &session.merkle_root,
            &hex::encode(sender.verifying_key.as_bytes()),
        )
        .unwrap();

        assert_eq!(decrypted, chunk_data[0]);
    }

    #[test]
    fn test_full_chunked_transfer() {
        let (sender, receiver) = setup_keypairs();
        // Create test data larger than one chunk
        let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect(); // 8KB with 2KB chunks

        let (session, chunk_data) =
            prepare_session(&sender, &receiver.did, "big.bin", "restricted", &data, 2048).unwrap();

        assert_eq!(session.total_chunks, 4); // 8192 / 2048

        // Encrypt all chunks
        let mut received_chunks = Vec::new();
        for i in 0..session.total_chunks {
            let encrypted = encrypt_chunk(
                &session,
                i,
                &chunk_data[i],
                &sender,
                &receiver.x25519_public_key_bytes(),
                Some(receiver.kyber_public.as_slice()),
            )
            .unwrap();

            let decrypted = receive_chunk(
                &receiver,
                &encrypted,
                &session.merkle_root,
                &hex::encode(sender.verifying_key.as_bytes()),
            )
            .unwrap();

            received_chunks.push(decrypted);
        }

        // Reassemble and verify
        let reassembled = reassemble_and_verify(
            &received_chunks,
            &session.merkle_root,
            &session.plaintext_sha256,
        )
        .unwrap();

        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_tampered_chunk_detected() {
        let (sender, receiver) = setup_keypairs();
        let data = b"sensitive data that must not be tampered";

        let (session, chunk_data) = prepare_session(
            &sender,
            &receiver.did,
            "test.txt",
            "confidential",
            data,
            1024,
        )
        .unwrap();

        let mut encrypted = encrypt_chunk(
            &session,
            0,
            &chunk_data[0],
            &sender,
            &receiver.x25519_public_key_bytes(),
            Some(receiver.kyber_public.as_slice()),
        )
        .unwrap();

        // Tamper with the encrypted data
        if !encrypted.encrypted_data.is_empty() {
            encrypted.encrypted_data[0] ^= 0xFF;
        }

        let result = receive_chunk(
            &receiver,
            &encrypted,
            &session.merkle_root,
            &hex::encode(sender.verifying_key.as_bytes()),
        );

        assert!(result.is_err(), "Tampered chunk should be detected");
    }

    #[test]
    fn test_session_persistence() {
        let (sender, _) = setup_keypairs();
        let data = b"test data for session persistence";

        let (session, _) =
            prepare_session(&sender, "did:nxf:recv", "file.txt", "internal", data, 1024).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = save_session(&session, dir.path()).unwrap();
        assert!(path.exists());

        let loaded = load_session(&session.session_id, dir.path()).unwrap();
        assert_eq!(loaded.session_id, session.session_id);
        assert_eq!(loaded.merkle_root, session.merkle_root);
    }

    #[test]
    fn test_merkle_proof_cache_matches_legacy_generation() {
        let (sender, receiver) = setup_keypairs();
        let data: Vec<u8> = (0..=255u8).cycle().take(10 * 1024).collect();

        let (session, chunk_data) = prepare_session(
            &sender,
            &receiver.did,
            "cached.bin",
            "internal",
            &data,
            2048,
        )
        .unwrap();
        let proof_cache = build_serialized_merkle_proof_cache(&session).unwrap();
        assert_eq!(proof_cache.len(), session.total_chunks);

        for (index, serialized_proof) in proof_cache.iter().enumerate() {
            let encrypted = encrypt_chunk_with_serialized_proof(
                &session,
                index,
                serialized_proof,
                &chunk_data[index],
                &sender,
                &receiver.x25519_public_key_bytes(),
                Some(receiver.kyber_public.as_slice()),
            )
            .unwrap();
            let decrypted = receive_chunk(
                &receiver,
                &encrypted,
                &session.merkle_root,
                &hex::encode(sender.verifying_key.as_bytes()),
            )
            .unwrap();
            assert_eq!(decrypted, chunk_data[index]);

            let legacy = encrypt_chunk(
                &session,
                index,
                &chunk_data[index],
                &sender,
                &receiver.x25519_public_key_bytes(),
                Some(receiver.kyber_public.as_slice()),
            )
            .unwrap();
            assert_eq!(encrypted.merkle_proof, legacy.merkle_proof);
        }
    }

    #[test]
    fn test_dynamic_padded_block_size_scales_with_chunk_size() {
        assert_eq!(
            padded_block_size_for_chunk_size(DEFAULT_CHUNK_SIZE),
            PADDED_BLOCK_SIZE
        );
        assert_eq!(
            padded_block_size_for_chunk_size(16 * 1024 * 1024),
            16 * 1024 * 1024 + 256 * 1024
        );
    }

    #[test]
    fn auto_resume_requires_matching_resume_token_and_sender() {
        let init = ChunkTransferInitPayload {
            session_id: "sess_resume".to_string(),
            artifact_id: "artifact".to_string(),
            filename: "file.bin".to_string(),
            classification: "internal".to_string(),
            total_size: 16,
            chunk_size: 8,
            total_chunks: 2,
            merkle_root: [7u8; 32],
            plaintext_sha256: "aa".repeat(32),
            sender_verifying_key_hex: "bb".repeat(32),
            version: 1,
            requires_reapproval: false,
            resume_requested: false,
            resume_token: "resume_token".to_string(),
        };
        let mut recv = ChunkedReceiveSession::new(
            init.clone(),
            "did:nxf:alice".to_string(),
            "alice".to_string(),
        )
        .unwrap();
        recv.store_chunk(0, b"chunk0".to_vec()).unwrap();

        let mut resume_init = init.clone();
        resume_init.resume_requested = true;
        assert!(recv.can_auto_resume(&resume_init, "did:nxf:alice"));

        let mut wrong_token = resume_init.clone();
        wrong_token.resume_token = "wrong".to_string();
        assert!(!recv.can_auto_resume(&wrong_token, "did:nxf:alice"));

        assert!(!recv.can_auto_resume(&resume_init, "did:nxf:bob"));
    }

    #[test]
    fn test_finalize_raw_payload_without_gzip_unpack() {
        use sha2::Digest;

        let raw_payload = b"PK\x03\x04fake zip payload bytes".to_vec();
        let sha256 = hex::encode(sha2::Sha256::digest(&raw_payload));
        let init = ChunkTransferInitPayload {
            session_id: format!("sess_{}", uuid::Uuid::new_v4()),
            artifact_id: format!("art_{}", uuid::Uuid::new_v4()),
            filename: "payload.zip".to_string(),
            classification: "confidential".to_string(),
            total_size: raw_payload.len() as u64,
            chunk_size: raw_payload.len(),
            total_chunks: 1,
            merkle_root: [0u8; 32],
            plaintext_sha256: sha256,
            sender_verifying_key_hex: "deadbeef".to_string(),
            version: 2,
            requires_reapproval: false,
            resume_requested: false,
            resume_token: "resume_test".to_string(),
        };

        let mut recv =
            ChunkedReceiveSession::new(init, "did:nxf:test".to_string(), "sender".to_string())
                .unwrap();
        recv.store_chunk(0, raw_payload.clone()).unwrap();
        assert!(recv.is_complete());

        let out = tempfile::tempdir().unwrap();
        let manifest = recv.finalize(out.path()).unwrap();
        let written = std::fs::read(out.path().join("payload.zip")).unwrap();

        assert_eq!(written, raw_payload);
        assert_eq!(manifest.total_size, raw_payload.len() as u64);
    }

    #[test]
    fn test_finalize_with_path_cleans_temp_chunk_staging_on_success() {
        use sha2::Digest;

        let raw_payload = b"PK\x03\x04fake zip payload bytes".to_vec();
        let sha256 = hex::encode(sha2::Sha256::digest(&raw_payload));
        let init = ChunkTransferInitPayload {
            session_id: format!("sess_{}", uuid::Uuid::new_v4()),
            artifact_id: format!("art_{}", uuid::Uuid::new_v4()),
            filename: "payload.zip".to_string(),
            classification: "confidential".to_string(),
            total_size: raw_payload.len() as u64,
            chunk_size: raw_payload.len(),
            total_chunks: 1,
            merkle_root: [0u8; 32],
            plaintext_sha256: sha256,
            sender_verifying_key_hex: "deadbeef".to_string(),
            version: 2,
            requires_reapproval: false,
            resume_requested: false,
            resume_token: "resume_test".to_string(),
        };

        let mut recv =
            ChunkedReceiveSession::new(init, "did:nxf:test".to_string(), "sender".to_string())
                .unwrap();
        let temp_dir = recv.temp_dir.clone();
        recv.store_chunk(0, raw_payload.clone()).unwrap();

        let out = tempfile::tempdir().unwrap();
        let (_, final_path) = recv.finalize_with_path(out.path()).unwrap();

        assert!(final_path.exists());
        assert_eq!(std::fs::read(final_path).unwrap(), raw_payload);
        assert!(
            !temp_dir.exists(),
            "temp chunk staging directory should be removed after successful finalize"
        );
    }

    #[test]
    fn test_finalize_raw_payload_renames_on_collision() {
        use sha2::Digest;

        let raw_payload = b"PK\x03\x04fake zip payload bytes".to_vec();
        let sha256 = hex::encode(sha2::Sha256::digest(&raw_payload));
        let build_recv = || {
            let init = ChunkTransferInitPayload {
                session_id: format!("sess_{}", uuid::Uuid::new_v4()),
                artifact_id: format!("art_{}", uuid::Uuid::new_v4()),
                filename: "payload.zip".to_string(),
                classification: "confidential".to_string(),
                total_size: raw_payload.len() as u64,
                chunk_size: raw_payload.len(),
                total_chunks: 1,
                merkle_root: [0u8; 32],
                plaintext_sha256: sha256.clone(),
                sender_verifying_key_hex: "deadbeef".to_string(),
                version: 2,
                requires_reapproval: false,
                resume_requested: false,
                resume_token: "resume_test".to_string(),
            };
            let mut recv =
                ChunkedReceiveSession::new(init, "did:nxf:test".to_string(), "sender".to_string())
                    .unwrap();
            recv.store_chunk(0, raw_payload.clone()).unwrap();
            recv
        };

        let out = tempfile::tempdir().unwrap();
        let (_, first_path) = build_recv().finalize_with_path(out.path()).unwrap();
        let (_, second_path) = build_recv().finalize_with_path(out.path()).unwrap();

        assert_eq!(first_path.file_name().unwrap(), "payload.zip");
        assert_eq!(second_path.file_name().unwrap(), "payload-2.zip");
        assert_eq!(std::fs::read(first_path).unwrap(), raw_payload);
        assert_eq!(std::fs::read(second_path).unwrap(), raw_payload);
    }

    #[test]
    fn pack_to_temp_file_preserves_selected_directory_name() {
        let dir = tempfile::tempdir().unwrap();
        let folder_path = dir.path().join("selected-folder");
        let nested_dir = folder_path.join("images");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(folder_path.join("cover.txt"), b"cover").unwrap();
        std::fs::write(nested_dir.join("photo.txt"), b"photo").unwrap();

        let packed_path = pack_to_temp_file(&folder_path).unwrap();
        let out = tempfile::tempdir().unwrap();
        crate::artifact::transfer::unpack_archive_file_public(&packed_path, out.path()).unwrap();

        assert_eq!(
            std::fs::read(out.path().join("selected-folder").join("cover.txt")).unwrap(),
            b"cover"
        );
        assert_eq!(
            std::fs::read(
                out.path()
                    .join("selected-folder")
                    .join("images")
                    .join("photo.txt")
            )
            .unwrap(),
            b"photo"
        );
    }

    #[test]
    fn test_finalize_archived_folder_renames_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        let folder_path = dir.path().join("selected-folder");
        let nested_dir = folder_path.join("images");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(folder_path.join("cover.txt"), b"cover").unwrap();
        std::fs::write(nested_dir.join("photo.txt"), b"photo").unwrap();

        let packed = crate::artifact::transfer::pack_path(&folder_path).unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(&packed));
        let build_recv = || {
            let init = ChunkTransferInitPayload {
                session_id: format!("sess_{}", uuid::Uuid::new_v4()),
                artifact_id: format!("art_{}", uuid::Uuid::new_v4()),
                filename: "selected-folder".to_string(),
                classification: "confidential".to_string(),
                total_size: packed.len() as u64,
                chunk_size: packed.len(),
                total_chunks: 1,
                merkle_root: [0u8; 32],
                plaintext_sha256: sha256.clone(),
                sender_verifying_key_hex: "deadbeef".to_string(),
                version: 2,
                requires_reapproval: false,
                resume_requested: false,
                resume_token: "resume_test".to_string(),
            };
            let mut recv =
                ChunkedReceiveSession::new(init, "did:nxf:test".to_string(), "sender".to_string())
                    .unwrap();
            recv.store_chunk(0, packed.clone()).unwrap();
            recv
        };

        let out = tempfile::tempdir().unwrap();
        let (_, first_path) = build_recv().finalize_with_path(out.path()).unwrap();
        let (_, second_path) = build_recv().finalize_with_path(out.path()).unwrap();

        assert_eq!(first_path.file_name().unwrap(), "selected-folder");
        assert_eq!(second_path.file_name().unwrap(), "selected-folder-2");
        assert_eq!(
            std::fs::read(second_path.join("cover.txt")).unwrap(),
            b"cover"
        );
        assert_eq!(
            std::fs::read(second_path.join("images").join("photo.txt")).unwrap(),
            b"photo"
        );
    }

    #[test]
    fn test_pending_chunks() {
        let (sender, _) = setup_keypairs();
        let data = vec![0u8; 4096];

        let (mut session, _) =
            prepare_session(&sender, "did:nxf:recv", "file.bin", "internal", &data, 1024).unwrap();

        assert_eq!(pending_chunk_indices(&session).len(), 4);

        // Mark some as acknowledged
        session.chunks[0].acknowledged = true;
        session.chunks[2].acknowledged = true;

        let pending = pending_chunk_indices(&session);
        assert_eq!(pending, vec![1, 3]);
    }
}

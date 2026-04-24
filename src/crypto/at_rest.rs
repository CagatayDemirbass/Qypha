use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::path::Path;
use zeroize::Zeroize;

use crate::crypto::identity::AgentKeyPair;
use crate::crypto::keystore::write_private_file;

const PERSIST_BLOB_MAGIC: &[u8; 8] = b"QLPSTV1!";
const NONCE_LEN: usize = 12;
const AAD_PREFIX: &[u8] = b"Qypha-AtRest-Persist-v1:";

pub(crate) fn derive_agent_scoped_persist_key(keypair: &AgentKeyPair, scope: &[u8]) -> [u8; 32] {
    let mut signing_key = keypair.signing_key.to_bytes();
    let mut encryption_secret = keypair.x25519_secret_key_bytes();
    let mut material = Vec::with_capacity(signing_key.len() + encryption_secret.len());
    material.extend_from_slice(&signing_key);
    material.extend_from_slice(&encryption_secret);
    signing_key.zeroize();
    encryption_secret.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(b"Qypha-AtRest-Persist-Key-v1"), &material);
    material.zeroize();

    let mut info = Vec::with_capacity(keypair.did.len() + scope.len() + 1);
    info.extend_from_slice(keypair.did.as_bytes());
    info.push(0);
    info.extend_from_slice(scope);

    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand for at-rest persistence key should not fail");
    info.zeroize();
    key
}

pub(crate) fn read_persisted_bytes(
    path: &Path,
    key: Option<&[u8; 32]>,
    scope: &[u8],
) -> Result<Option<Vec<u8>>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to read persisted state file {}", path.display())
            });
        }
    };

    if !is_encrypted_persist_blob(&bytes) {
        return Ok(Some(bytes));
    }

    let key = key.ok_or_else(|| {
        anyhow::anyhow!(
            "Persisted state {} is encrypted but no persistence key is available",
            path.display()
        )
    })?;
    decrypt_persisted_blob(key, scope, &bytes).map(Some)
}

pub(crate) fn write_persisted_bytes(
    path: &Path,
    key: Option<&[u8; 32]>,
    scope: &[u8],
    plaintext: &[u8],
) -> Result<()> {
    let encoded = match key {
        Some(key) => encrypt_persisted_blob(key, scope, plaintext)?,
        None => plaintext.to_vec(),
    };

    write_private_file(path, &encoded)
        .with_context(|| format!("Failed to persist state file {}", path.display()))?;

    Ok(())
}

fn encrypt_persisted_blob(key: &[u8; 32], scope: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce_bytes = rand::random::<[u8; NONCE_LEN]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = aad_for_scope(scope);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Persisted state encryption failed"))?;

    let mut blob = Vec::with_capacity(PERSIST_BLOB_MAGIC.len() + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(PERSIST_BLOB_MAGIC);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt_persisted_blob(key: &[u8; 32], scope: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < PERSIST_BLOB_MAGIC.len() + NONCE_LEN + 16 {
        return Err(anyhow::anyhow!("Persisted state blob too short"));
    }

    let nonce_start = PERSIST_BLOB_MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
    let ciphertext = &blob[nonce_end..];
    let aad = aad_for_scope(scope);
    let cipher = Aes256Gcm::new_from_slice(key)?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Persisted state blob failed integrity check"))
}

fn is_encrypted_persist_blob(blob: &[u8]) -> bool {
    blob.starts_with(PERSIST_BLOB_MAGIC)
}

fn aad_for_scope(scope: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + scope.len());
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(scope);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_blob_roundtrip_succeeds() {
        let key = [7u8; 32];
        let scope = b"test-scope";
        let plaintext = br#"{"ok":true}"#;

        let blob = encrypt_persisted_blob(&key, scope, plaintext).unwrap();
        assert!(is_encrypted_persist_blob(&blob));
        let decoded = decrypt_persisted_blob(&key, scope, &blob).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn read_persisted_bytes_accepts_legacy_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.json");
        std::fs::write(&path, br#"["invite-a"]"#).unwrap();

        let loaded = read_persisted_bytes(&path, Some(&[9u8; 32]), b"legacy").unwrap();
        assert_eq!(loaded.unwrap(), br#"["invite-a"]"#);
    }

    #[test]
    fn encrypted_blob_requires_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        write_persisted_bytes(&path, Some(&[5u8; 32]), b"scope", b"secret").unwrap();

        let error = read_persisted_bytes(&path, None, b"scope").unwrap_err();
        assert!(error
            .to_string()
            .contains("is encrypted but no persistence key is available"));
    }
}

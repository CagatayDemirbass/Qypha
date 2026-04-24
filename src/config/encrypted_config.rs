use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

const ENC_PREFIX: &str = "ENC:";
const V2_MAGIC: &[u8; 8] = b"QLCFGV2!";
const V2_AAD: &[u8] = b"Qypha-Config-Encryption-v2";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Encrypted configuration field support.
///
/// Sensitive values in TOML config files can be encrypted using AES-256-GCM
/// with a master passphrase. New values are stored as:
/// `ENC:<base64(magic || salt || nonce || ciphertext)>`
///
/// Key derivation:
/// - Argon2id + random salt embedded in each ENC blob
/// - bulk config writes may reuse one derived key/salt across multiple fields
///   to avoid paying full Argon2 cost per field
pub struct EncryptedConfigLoader;

pub(crate) struct ConfigFieldCipher {
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
}

impl EncryptedConfigLoader {
    /// Encrypt a plaintext value using the master passphrase.
    /// Returns a string in the format "ENC:<base64>"
    pub fn encrypt_value(passphrase: &str, plaintext: &str) -> Result<String> {
        Self::batch_encryptor(passphrase)?.encrypt_value(plaintext)
    }

    /// Decrypt an encrypted config value.
    /// Input should be "ENC:<base64>" format.
    pub fn decrypt_value(passphrase: &str, encrypted: &str) -> Result<String> {
        Self::decryptor_for_encrypted_value(passphrase, encrypted)?.decrypt_value(encrypted)
    }

    /// Check if a string value is encrypted
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENC_PREFIX)
    }

    /// Decrypt a value if it's encrypted, otherwise return as-is
    pub fn decrypt_if_encrypted(passphrase: &str, value: &str) -> Result<String> {
        if Self::is_encrypted(value) {
            Self::decrypt_value(passphrase, value)
        } else {
            Ok(value.to_string())
        }
    }

    pub(crate) fn batch_encryptor(passphrase: &str) -> Result<ConfigFieldCipher> {
        Self::ensure_passphrase(passphrase)?;
        let salt = rand::random::<[u8; SALT_LEN]>();
        let key = Zeroizing::new(Self::derive_v2_key(passphrase, &salt)?);
        Ok(ConfigFieldCipher { salt, key })
    }

    pub(crate) fn decryptor_for_encrypted_value(
        passphrase: &str,
        encrypted: &str,
    ) -> Result<ConfigFieldCipher> {
        Self::ensure_passphrase(passphrase)?;
        let salt = Self::salt_from_encrypted_value(encrypted)?;
        let key = Zeroizing::new(Self::derive_v2_key(passphrase, &salt)?);
        Ok(ConfigFieldCipher { salt, key })
    }

    pub(crate) fn cache_key_for_encrypted_value(encrypted: &str) -> Result<String> {
        Ok(base64::engine::general_purpose::STANDARD
            .encode(Self::salt_from_encrypted_value(encrypted)?))
    }

    fn salt_from_encrypted_value(encrypted: &str) -> Result<[u8; SALT_LEN]> {
        let blob = Self::decode_encrypted_blob(encrypted)?;
        Ok(Self::parse_v2_blob(&blob)?.salt)
    }

    fn encode_encrypted_blob(
        salt: &[u8; SALT_LEN],
        nonce_bytes: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> String {
        let mut blob = Vec::with_capacity(V2_MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(V2_MAGIC);
        blob.extend_from_slice(salt);
        blob.extend_from_slice(nonce_bytes);
        blob.extend_from_slice(ciphertext);

        format!(
            "{}{}",
            ENC_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    fn decode_encrypted_blob(encrypted: &str) -> Result<Vec<u8>> {
        let encoded = encrypted
            .strip_prefix(ENC_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("Value is not encrypted (no ENC: prefix)"))?;

        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))
    }

    fn parse_v2_blob(blob: &[u8]) -> Result<ParsedV2Blob<'_>> {
        if !blob.starts_with(V2_MAGIC) {
            return Err(anyhow::anyhow!(
                "Unsupported encrypted config format; re-encrypt with the current Argon2id format"
            ));
        }

        let min_len = V2_MAGIC.len() + SALT_LEN + NONCE_LEN + 16;
        if blob.len() < min_len {
            return Err(anyhow::anyhow!("Encrypted v2 value too short"));
        }

        let salt_start = V2_MAGIC.len();
        let salt_end = salt_start + SALT_LEN;
        let nonce_end = salt_end + NONCE_LEN;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&blob[salt_start..salt_end]);

        Ok(ParsedV2Blob {
            salt,
            nonce_bytes: &blob[salt_end..nonce_end],
            ciphertext: &blob[nonce_end..],
        })
    }

    fn encrypt_with_key_material(
        key: &[u8],
        salt: &[u8; SALT_LEN],
        plaintext: &str,
    ) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce_bytes = rand::random::<[u8; NONCE_LEN]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: V2_AAD,
                },
            )
            .map_err(|e| anyhow::anyhow!("Config encrypt failed: {}", e))?;

        Ok(Self::encode_encrypted_blob(salt, &nonce_bytes, &ciphertext))
    }

    fn decrypt_with_key_material(key: &[u8], parsed: ParsedV2Blob<'_>) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(parsed.nonce_bytes);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: parsed.ciphertext,
                    aad: V2_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("Config decrypt failed — wrong passphrase?"))?;

        String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("Decrypted value is not valid UTF-8: {}", e))
    }

    fn derive_v2_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        Self::strong_config_argon2()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;
        Ok(key)
    }

    fn strong_config_argon2() -> Argon2<'static> {
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(256 * 1024, 4, 4, Some(32)).expect("valid Argon2 params"),
        )
    }

    fn ensure_passphrase(passphrase: &str) -> Result<()> {
        if passphrase.trim().is_empty() {
            return Err(anyhow::anyhow!("Passphrase must not be empty"));
        }
        Ok(())
    }
}

impl ConfigFieldCipher {
    pub(crate) fn encrypt_value(&self, plaintext: &str) -> Result<String> {
        EncryptedConfigLoader::encrypt_with_key_material(&self.key[..], &self.salt, plaintext)
    }

    pub(crate) fn decrypt_value(&self, encrypted: &str) -> Result<String> {
        let blob = EncryptedConfigLoader::decode_encrypted_blob(encrypted)?;
        let parsed = EncryptedConfigLoader::parse_v2_blob(&blob)?;
        if parsed.salt != self.salt {
            return Err(anyhow::anyhow!(
                "Encrypted config value does not match the cached field cipher"
            ));
        }
        EncryptedConfigLoader::decrypt_with_key_material(&self.key[..], parsed)
    }
}

struct ParsedV2Blob<'a> {
    salt: [u8; SALT_LEN],
    nonce_bytes: &'a [u8],
    ciphertext: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let passphrase = "my_secret_passphrase";
        let plaintext = "super_secret_api_key_12345";

        let encrypted = EncryptedConfigLoader::encrypt_value(passphrase, plaintext).unwrap();
        assert!(encrypted.starts_with("ENC:"));
        assert_ne!(encrypted, plaintext);
        assert!(!encrypted.contains(plaintext));

        let decrypted = EncryptedConfigLoader::decrypt_value(passphrase, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let encrypted = EncryptedConfigLoader::encrypt_value("correct", "secret").unwrap();
        let result = EncryptedConfigLoader::decrypt_value("wrong", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_legacy_blob_is_rejected() {
        let legacy_like = format!(
            "{}{}",
            ENC_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(b"old-format-ciphertext")
        );
        let result = EncryptedConfigLoader::decrypt_value("legacy-pass", &legacy_like);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_encrypted() {
        assert!(EncryptedConfigLoader::is_encrypted("ENC:abc123"));
        assert!(!EncryptedConfigLoader::is_encrypted("plain_text"));
    }

    #[test]
    fn test_decrypt_if_encrypted_plain() {
        let result = EncryptedConfigLoader::decrypt_if_encrypted("pass", "plain_value").unwrap();
        assert_eq!(result, "plain_value");
    }

    #[test]
    fn test_decrypt_if_encrypted_enc() {
        let encrypted = EncryptedConfigLoader::encrypt_value("pass", "secret").unwrap();
        let result = EncryptedConfigLoader::decrypt_if_encrypted("pass", &encrypted).unwrap();
        assert_eq!(result, "secret");
    }

    #[test]
    fn test_empty_passphrase_is_rejected() {
        let result = EncryptedConfigLoader::encrypt_value("   ", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_encryptor_reuses_one_salt_for_multiple_values() {
        let cipher = EncryptedConfigLoader::batch_encryptor("batch-pass").unwrap();
        let encrypted_a = cipher.encrypt_value("alpha").unwrap();
        let encrypted_b = cipher.encrypt_value("bravo").unwrap();

        let cache_a = EncryptedConfigLoader::cache_key_for_encrypted_value(&encrypted_a).unwrap();
        let cache_b = EncryptedConfigLoader::cache_key_for_encrypted_value(&encrypted_b).unwrap();
        assert_eq!(cache_a, cache_b);

        let decryptor =
            EncryptedConfigLoader::decryptor_for_encrypted_value("batch-pass", &encrypted_a)
                .unwrap();
        assert_eq!(decryptor.decrypt_value(&encrypted_a).unwrap(), "alpha");
        assert_eq!(decryptor.decrypt_value(&encrypted_b).unwrap(), "bravo");
    }
}

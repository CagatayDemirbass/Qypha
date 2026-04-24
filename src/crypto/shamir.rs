//! Shamir Secret Sharing for threshold decryption of shadow audit logs.
//!
//! Implements a (k, n) threshold scheme where:
//!   - A secret (e.g., AES-256 key) is split into `n` shares
//!   - Any `k` shares can reconstruct the secret
//!   - Fewer than `k` shares reveal ZERO information about the secret
//!
//! Default: (2, 3) — 3 executives hold shares, 2 must cooperate to decrypt.
//! This ensures:
//!   - No single executive can unilaterally access shadow audit logs
//!   - The system tolerates 1 compromised/unavailable executive
//!   - Even state-level adversaries need to compromise 2 separate individuals

use anyhow::{Context, Result};
use sharks::{Share, Sharks};

/// Default threshold: 2 of 3 shares required
pub const DEFAULT_THRESHOLD: u8 = 2;
/// Default total shares
pub const DEFAULT_SHARES: usize = 3;

/// Split a secret into `n` shares with threshold `k`.
///
/// Returns a vector of serialized shares (each is a self-contained byte vec).
/// Any `k` shares can reconstruct the original secret.
///
/// # Security
/// Uses GF(256) polynomial interpolation — information-theoretically secure.
/// With k-1 shares, the attacker has ZERO bits of information about the secret.
pub fn split_secret(secret: &[u8], threshold: u8, total_shares: usize) -> Result<Vec<Vec<u8>>> {
    if threshold < 2 {
        return Err(anyhow::anyhow!("Threshold must be at least 2"));
    }
    if (total_shares as u8) < threshold {
        return Err(anyhow::anyhow!(
            "Total shares ({}) must be >= threshold ({})",
            total_shares,
            threshold
        ));
    }
    if secret.is_empty() {
        return Err(anyhow::anyhow!("Secret must not be empty"));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);

    let shares: Vec<Vec<u8>> = dealer
        .take(total_shares)
        .map(|share| Vec::from(&share))
        .collect();

    Ok(shares)
}

/// Reconstruct a secret from `k` or more shares.
///
/// Returns the original secret bytes. Fails if fewer than threshold shares
/// are provided or if shares are corrupted/incompatible.
pub fn reconstruct_secret(shares: &[Vec<u8>], threshold: u8) -> Result<Vec<u8>> {
    if shares.len() < threshold as usize {
        return Err(anyhow::anyhow!(
            "Need at least {} shares, got {}",
            threshold,
            shares.len()
        ));
    }

    let sharks = Sharks(threshold);

    let parsed_shares: Vec<Share> = shares
        .iter()
        .map(|s| Share::try_from(s.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Invalid share format: {}", e))?;

    let secret = sharks
        .recover(&parsed_shares)
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct secret: {}", e))?;

    Ok(secret)
}

/// Split an AES-256 key into shares using the default (2, 3) scheme.
///
/// Convenience wrapper for the common case: 3 executive shares, 2 needed.
pub fn split_aes_key(key: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    split_secret(key, DEFAULT_THRESHOLD, DEFAULT_SHARES)
}

/// Reconstruct an AES-256 key from shares.
///
/// Returns a 32-byte key or error if reconstruction fails.
pub fn reconstruct_aes_key(shares: &[Vec<u8>]) -> Result<[u8; 32]> {
    let secret = reconstruct_secret(shares, DEFAULT_THRESHOLD)?;
    let key: [u8; 32] = secret.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "Reconstructed key has wrong length: expected 32, got {}",
            v.len()
        )
    })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct_2_of_3() {
        let secret = b"TOP SECRET AES KEY 1234567890AB"; // 30 bytes
        let shares = split_secret(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct
        let recovered = reconstruct_secret(&shares[0..2], 2).unwrap();
        assert_eq!(recovered, secret);

        let recovered2 = reconstruct_secret(&shares[1..3], 2).unwrap();
        assert_eq!(recovered2, secret);

        let recovered3 = reconstruct_secret(&[shares[0].clone(), shares[2].clone()], 2).unwrap();
        assert_eq!(recovered3, secret);
    }

    #[test]
    fn test_split_aes_key() {
        let key: [u8; 32] = rand::random();
        let shares = split_aes_key(&key).unwrap();
        assert_eq!(shares.len(), 3);

        // Reconstruct with 2 shares
        let recovered = reconstruct_aes_key(&shares[0..2]).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_insufficient_shares_fails() {
        let secret = b"secret data";
        let shares = split_secret(secret, 3, 5).unwrap();

        // 2 shares (less than threshold 3) should fail
        let result = reconstruct_secret(&shares[0..2], 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_shares_reconstruct() {
        let secret = b"all shares test";
        let shares = split_secret(secret, 2, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // All 5 shares should also work
        let recovered = reconstruct_secret(&shares, 2).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_threshold_must_be_at_least_2() {
        let result = split_secret(b"test", 1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_shares_less_than_threshold_fails() {
        let result = split_secret(b"test", 3, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_secret_fails() {
        let result = split_secret(b"", 2, 3);
        assert!(result.is_err());
    }
}

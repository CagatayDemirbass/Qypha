use std::collections::VecDeque;

/// Sliding-window replay protection for agent messages.
///
/// Tracks seen (nonce, timestamp) pairs within a configurable time window.
/// Rejects:
///   1. Duplicate nonces within the window
///   2. Messages with timestamps too far in the past
///   3. Messages that have expired (TTL exceeded)
pub struct ReplayGuard {
    /// Recent (nonce, timestamp_ms) pairs
    seen: VecDeque<(u64, u64)>,
    /// Maximum age of a valid message (milliseconds)
    max_age_ms: u64,
    /// Maximum number of nonces to track
    window_size: usize,
}

#[derive(Debug, PartialEq)]
pub enum ReplayError {
    /// This nonce was already seen (replay attack)
    DuplicateNonce,
    /// Message timestamp is too old
    ExpiredTimestamp,
    /// Message timestamp is implausibly in the future
    FutureTimestamp,
    /// Message TTL has been exceeded
    TtlExceeded,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateNonce => write!(f, "duplicate nonce — possible replay attack"),
            Self::ExpiredTimestamp => write!(f, "message timestamp too old"),
            Self::FutureTimestamp => write!(f, "message timestamp too far in the future"),
            Self::TtlExceeded => write!(f, "message TTL exceeded"),
        }
    }
}

impl ReplayGuard {
    /// Create a new ReplayGuard.
    ///
    /// `window_size` — max number of nonces to track (older ones are evicted)
    /// `max_age_ms`  — messages older than this are rejected
    pub fn new(window_size: usize, max_age_ms: u64) -> Self {
        Self {
            seen: VecDeque::with_capacity(window_size),
            max_age_ms,
            window_size,
        }
    }

    /// Check if a message with the given nonce and timestamp is valid,
    /// and record it if so.
    ///
    /// `ttl_ms` — if > 0, the message is rejected if current_time > timestamp + ttl_ms
    pub fn check_and_record(
        &mut self,
        nonce: u64,
        timestamp: u64,
        ttl_ms: u64,
    ) -> Result<(), ReplayError> {
        let now = current_time_ms();
        const MAX_FUTURE_SKEW_MS: u64 = 300_000; // 5 minutes

        // Check timestamp age
        if now > timestamp && (now - timestamp) > self.max_age_ms {
            return Err(ReplayError::ExpiredTimestamp);
        }

        // Reject implausible future timestamps (clock skew allowance).
        if timestamp > now && (timestamp - now) > MAX_FUTURE_SKEW_MS {
            return Err(ReplayError::FutureTimestamp);
        }

        // Check TTL
        if ttl_ms > 0 && now > timestamp.saturating_add(ttl_ms) {
            return Err(ReplayError::TtlExceeded);
        }

        // Cleanup old entries
        self.cleanup(now);

        // Check for duplicate nonce
        if self.seen.iter().any(|(n, _)| *n == nonce) {
            return Err(ReplayError::DuplicateNonce);
        }

        // Record this nonce
        self.seen.push_back((nonce, timestamp));

        // Evict oldest if over capacity
        while self.seen.len() > self.window_size {
            self.seen.pop_front();
        }

        Ok(())
    }

    /// Remove entries older than max_age_ms
    fn cleanup(&mut self, now: u64) {
        while let Some(&(_, ts)) = self.seen.front() {
            if now > ts && (now - ts) > self.max_age_ms {
                self.seen.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of nonces currently tracked
    pub fn tracked_count(&self) -> usize {
        self.seen.len()
    }

    /// Persist the replay guard state to disk (AES-256-GCM encrypted).
    ///
    /// Used in Full mode to survive restarts — prevents replay
    /// attacks that exploit daemon restart to clear the nonce window.
    /// Ghost mode should NOT call this (zero disk writes).
    pub fn persist(&self, path: &std::path::Path, key: &[u8; 32]) -> Result<(), String> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        // Serialize nonces as compact binary: (nonce: u64, timestamp: u64) pairs
        let mut data = Vec::with_capacity(self.seen.len() * 16 + 16);
        data.extend_from_slice(&(self.seen.len() as u64).to_le_bytes());
        data.extend_from_slice(&self.max_age_ms.to_le_bytes());
        for &(nonce, ts) in &self.seen {
            data.extend_from_slice(&nonce.to_le_bytes());
            data.extend_from_slice(&ts.to_le_bytes());
        }

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key error: {}", e))?;
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data.as_slice())
            .map_err(|e| format!("Encrypt error: {}", e))?;

        // Write: nonce (12) || ciphertext
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ciphertext);
        std::fs::write(path, &out).map_err(|e| format!("Write error: {}", e))?;
        Ok(())
    }

    /// Load persisted replay guard state from disk.
    ///
    /// Returns None if the file doesn't exist or can't be decrypted.
    pub fn load_persisted(
        path: &std::path::Path,
        key: &[u8; 32],
        window_size: usize,
    ) -> Option<Self> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        let blob = std::fs::read(path).ok()?;
        if blob.len() < 12 {
            return None;
        }

        let nonce = Nonce::from_slice(&blob[..12]);
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let data = cipher.decrypt(nonce, &blob[12..]).ok()?;

        if data.len() < 16 {
            return None;
        }

        let count = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let max_age_ms = u64::from_le_bytes(data[8..16].try_into().ok()?);

        let mut seen = VecDeque::with_capacity(count.min(window_size));
        let now = current_time_ms();

        for i in 0..count {
            let offset = 16 + i * 16;
            if offset + 16 > data.len() {
                break;
            }
            let nonce_val = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
            let ts = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().ok()?);

            // Only load entries that haven't expired
            if now <= ts || (now - ts) <= max_age_ms {
                seen.push_back((nonce_val, ts));
            }
        }

        // Trim to window size
        while seen.len() > window_size {
            seen.pop_front();
        }

        Some(Self {
            seen,
            max_age_ms,
            window_size,
        })
    }
}

/// Current time in milliseconds (Unix epoch)
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        current_time_ms()
    }

    #[test]
    fn test_accept_valid_message() {
        let mut guard = ReplayGuard::new(100, 60_000);
        let ts = now_ms();
        assert!(guard.check_and_record(1, ts, 0).is_ok());
    }

    #[test]
    fn test_reject_duplicate_nonce() {
        let mut guard = ReplayGuard::new(100, 60_000);
        let ts = now_ms();
        assert!(guard.check_and_record(42, ts, 0).is_ok());
        assert_eq!(
            guard.check_and_record(42, ts, 0).unwrap_err(),
            ReplayError::DuplicateNonce
        );
    }

    #[test]
    fn test_reject_expired_timestamp() {
        let mut guard = ReplayGuard::new(100, 5_000); // 5 second window
        let old_ts = now_ms() - 10_000; // 10 seconds ago
        assert_eq!(
            guard.check_and_record(1, old_ts, 0).unwrap_err(),
            ReplayError::ExpiredTimestamp
        );
    }

    #[test]
    fn test_reject_ttl_exceeded() {
        let mut guard = ReplayGuard::new(100, 60_000);
        let old_ts = now_ms() - 3_000; // 3 seconds ago
                                       // TTL of 1 second — message expired 2 seconds ago
        assert_eq!(
            guard.check_and_record(1, old_ts, 1_000).unwrap_err(),
            ReplayError::TtlExceeded
        );
    }

    #[test]
    fn test_accept_within_ttl() {
        let mut guard = ReplayGuard::new(100, 60_000);
        let ts = now_ms() - 500; // 0.5 seconds ago
                                 // TTL of 5 seconds — still valid
        assert!(guard.check_and_record(1, ts, 5_000).is_ok());
    }

    #[test]
    fn test_reject_future_timestamp_beyond_skew() {
        let mut guard = ReplayGuard::new(100, 60_000);
        let future_ts = now_ms() + 301_000; // >5 min in future
        assert_eq!(
            guard.check_and_record(1, future_ts, 0).unwrap_err(),
            ReplayError::FutureTimestamp
        );
    }

    #[test]
    fn test_window_eviction() {
        let mut guard = ReplayGuard::new(3, 60_000); // tiny window
        let ts = now_ms();
        assert!(guard.check_and_record(1, ts, 0).is_ok());
        assert!(guard.check_and_record(2, ts, 0).is_ok());
        assert!(guard.check_and_record(3, ts, 0).is_ok());
        // Window full, oldest (nonce=1) should be evicted
        assert!(guard.check_and_record(4, ts, 0).is_ok());
        assert_eq!(guard.tracked_count(), 3);
        // nonce=1 was evicted, so it would be accepted again
        // (this is expected behavior — window-based, not permanent)
        assert!(guard.check_and_record(1, ts, 0).is_ok());
    }

    #[test]
    fn test_different_nonces_accepted() {
        let mut guard = ReplayGuard::new(100, 60_000);
        let ts = now_ms();
        for i in 0..50 {
            assert!(guard.check_and_record(i, ts, 0).is_ok());
        }
        assert_eq!(guard.tracked_count(), 50);
    }
}

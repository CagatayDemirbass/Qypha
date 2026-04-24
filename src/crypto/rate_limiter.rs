use std::collections::{HashMap, VecDeque};

/// Per-agent rate limiter using a sliding window algorithm.
///
/// Tracks request timestamps per agent DID and rejects requests
/// that exceed the configured rate.
pub struct RateLimiter {
    /// agent_did -> timestamps of recent requests (ms)
    buckets: HashMap<String, VecDeque<u64>>,
    /// Maximum requests allowed per window
    max_requests: usize,
    /// Window duration in milliseconds
    window_ms: u64,
}

#[derive(Debug, PartialEq)]
pub struct RateLimitError {
    pub agent_did: String,
    pub requests_in_window: usize,
    pub max_allowed: usize,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rate limit exceeded for {}: {}/{} requests in window",
            self.agent_did, self.requests_in_window, self.max_allowed
        )
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_requests` — maximum requests per window per agent
    /// `window_seconds` — window duration in seconds
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            buckets: HashMap::new(),
            max_requests,
            window_ms: window_seconds * 1000,
        }
    }

    /// Check if a request from this agent is allowed, and record it if so.
    pub fn check_and_record(&mut self, agent_did: &str) -> Result<(), RateLimitError> {
        let now = current_time_ms();
        let bucket = self.buckets.entry(agent_did.to_string()).or_default();

        // Remove expired entries
        let cutoff = now.saturating_sub(self.window_ms);
        while let Some(&ts) = bucket.front() {
            if ts < cutoff {
                bucket.pop_front();
            } else {
                break;
            }
        }

        // Check limit
        if bucket.len() >= self.max_requests {
            return Err(RateLimitError {
                agent_did: agent_did.to_string(),
                requests_in_window: bucket.len(),
                max_allowed: self.max_requests,
            });
        }

        // Record request
        bucket.push_back(now);
        Ok(())
    }

    /// Get the current request count for an agent
    pub fn current_count(&self, agent_did: &str) -> usize {
        self.buckets.get(agent_did).map_or(0, |b| b.len())
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_under_limit() {
        let mut rl = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(rl.check_and_record("did:nxf:test").is_ok());
        }
    }

    #[test]
    fn test_reject_over_limit() {
        let mut rl = RateLimiter::new(3, 60);
        assert!(rl.check_and_record("did:nxf:test").is_ok());
        assert!(rl.check_and_record("did:nxf:test").is_ok());
        assert!(rl.check_and_record("did:nxf:test").is_ok());
        let err = rl.check_and_record("did:nxf:test").unwrap_err();
        assert_eq!(err.max_allowed, 3);
        assert_eq!(err.requests_in_window, 3);
    }

    #[test]
    fn test_separate_buckets_per_agent() {
        let mut rl = RateLimiter::new(2, 60);
        assert!(rl.check_and_record("did:nxf:agent1").is_ok());
        assert!(rl.check_and_record("did:nxf:agent1").is_ok());
        // agent1 is at limit
        assert!(rl.check_and_record("did:nxf:agent1").is_err());
        // agent2 is fine
        assert!(rl.check_and_record("did:nxf:agent2").is_ok());
    }

    #[test]
    fn test_current_count() {
        let mut rl = RateLimiter::new(10, 60);
        assert_eq!(rl.current_count("did:nxf:test"), 0);
        rl.check_and_record("did:nxf:test").unwrap();
        assert_eq!(rl.current_count("did:nxf:test"), 1);
    }

    #[test]
    fn test_clear() {
        let mut rl = RateLimiter::new(10, 60);
        rl.check_and_record("did:nxf:test").unwrap();
        rl.clear();
        assert_eq!(rl.current_count("did:nxf:test"), 0);
    }
}

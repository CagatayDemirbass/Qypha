use std::sync::atomic::{AtomicU64, Ordering};

static LAST_REQUEST_NONCE: AtomicU64 = AtomicU64::new(0);

pub fn next_request_nonce() -> u64 {
    loop {
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let previous = LAST_REQUEST_NONCE.load(Ordering::Relaxed);
        let candidate = now.max(previous.saturating_add(1));
        match LAST_REQUEST_NONCE.compare_exchange(
            previous,
            candidate,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => return candidate,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::next_request_nonce;

    #[test]
    fn request_nonces_are_monotonic_even_with_same_millisecond_clock() {
        let first = next_request_nonce();
        let second = next_request_nonce();
        let third = next_request_nonce();

        assert!(second > first);
        assert!(third > second);
    }
}

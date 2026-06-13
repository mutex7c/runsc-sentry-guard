// Defensive Back-Pressure & Rate Limiting Controls
// Protects host resources from token exhaustion and high-frequency regex validation flood attacks

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// Silences dead-code warnings on cross-platform dev environments (macOS/Windows)
// where the Linux-only anti-spoofing engine block is compiled out
#[allow(dead_code)]
pub const MAX_NEGATIVE_CACHE: usize = 1000;
#[allow(dead_code)]
pub const MAX_LOOKUP_TOKENS: u32 = 10; // Max Docker API queries per second for unknown IDs

// Anti-DoS State Engine controlling the TOCTOU synchronous container lookup fallback cache
#[allow(dead_code)]
pub struct AntiDosState {
    pub negative_cache: HashSet<String>,
    pub negative_queue: VecDeque<String>,
    pub tokens: u32,
    pub last_refill: Instant,
}

impl AntiDosState {
    pub fn new() -> Self {
        Self {
            negative_cache: HashSet::new(),
            negative_queue: VecDeque::new(),
            tokens: MAX_LOOKUP_TOKENS,
            last_refill: Instant::now(),
        }
    }
}

// Global Sliding-Window Rate Limiting Tracker to protect host CPU against denial-of-service attempts
pub struct GlobalRateLimiter {
    state: Mutex<(Instant, usize)>,
    last_warning: Mutex<Instant>,
    max_per_second: usize,
}

impl GlobalRateLimiter {
    pub fn new(max_per_second: usize) -> Self {
        Self {
            state: Mutex::new((Instant::now(), 0)),
            last_warning: Mutex::new(Instant::now() - Duration::from_secs(5)),
            max_per_second,
        }
    }

    pub fn acquire(&self) -> bool {
        let mut guard = self.state.lock().expect("Global rate limiter lock poisoned");
        let now = Instant::now();

        // Reset the window count bucket if a full second has passed
        if now.duration_since(guard.0) >= Duration::from_secs(1) {
            guard.0 = now;
            guard.1 = 0;
        }

        if guard.1 < self.max_per_second {
            guard.1 += 1;
            true
        } else {
            false
        }
    }

    // Extends a 5-second cooldown delay threshold to prevent warning log exhaustion.
    pub fn should_warn(&self) -> bool {
        let mut guard = self.last_warning.lock().expect("Rate limiter warning lock poisoned");
        let now = Instant::now();
        if now.duration_since(*guard) >= Duration::from_secs(5) {
            *guard = now;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_rate_limiter_ceilings() {
        // Enforce a strict maximum cap threshold of 5 logs per window interval
        let limiter = GlobalRateLimiter::new(5);

        for _ in 0..5 {
            assert!(limiter.acquire(), "Limiter should allow acquisition under the metric ceiling.");
        }

        assert!(
            !limiter.acquire(),
            "VULNERABILITY REGRESSION: Limiter failed to drop excess tokens past safety boundary!"
        );
    }

    #[test]
    fn test_global_rate_limiter_warning_cooldowns() {
        let limiter = GlobalRateLimiter::new(10);

        // First assertion must immediately trigger true
        assert!(limiter.should_warn(), "Initial warning track should report true.");

        // Immediate subsequent calls must evaluate false to protect standard error log channels from exhaustion
        assert!(
            !limiter.should_warn(),
            "Rate limiter warning block did not enforce its 5-second cooldown delay threshold!"
        );
    }

    #[test]
    fn test_anti_dos_state_initialization() {
        let state = AntiDosState::new();
        assert_eq!(state.tokens, MAX_LOOKUP_TOKENS, "Token pool should match static boundaries.");
        assert!(state.negative_cache.is_empty(), "Negative lookup caches must boot pristine.");
    }
}
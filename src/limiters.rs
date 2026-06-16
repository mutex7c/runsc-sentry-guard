use parking_lot::Mutex;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

#[allow(dead_code)]
pub const MAX_NEGATIVE_CACHE: usize = 1000;
#[allow(dead_code)]
pub const MAX_LOOKUP_TOKENS: u32 = 10;

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
        let mut guard = self.state.lock();
        let now = Instant::now();

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

    pub fn should_warn(&self) -> bool {
        let mut guard = self.last_warning.lock();
        let now = Instant::now();
        if now.duration_since(*guard) >= Duration::from_secs(5) {
            *guard = now;
            true
        } else {
            false
        }
    }
}

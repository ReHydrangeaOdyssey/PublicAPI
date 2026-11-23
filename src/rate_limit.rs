use crate::rpc::Failure;
use axum::http::StatusCode;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
const MAX_BUCKETS: usize = 100_000;
pub struct RateLimit {
    buckets: HashMap<String, (Instant, u32)>,
    limit: u32,
    window: Duration,
}
impl RateLimit {
    pub fn new(limit: u32, window: Duration) -> Result<Self, crate::transport::Error> {
        if limit == 0 || window.is_zero() {
            return Err("invalid rate limit".into());
        }
        Ok(Self {
            buckets: HashMap::new(),
            limit,
            window,
        })
    }
    pub fn check(&mut self, key: String) -> Result<(), Failure> {
        let now = Instant::now();
        if self.buckets.len() == MAX_BUCKETS {
            self.buckets
                .retain(|_, (started, _)| now.duration_since(*started) < self.window);
            if self.buckets.len() == MAX_BUCKETS && !self.buckets.contains_key(&key) {
                return Err(Failure(StatusCode::TOO_MANY_REQUESTS, 22));
            }
        }
        let (started, count) = self.buckets.entry(key).or_insert((now, 0));
        if now.duration_since(*started) >= self.window {
            *started = now;
            *count = 0;
        }
        if *count >= self.limit {
            return Err(Failure(StatusCode::TOO_MANY_REQUESTS, 22));
        }
        *count += 1;
        Ok(())
    }
}

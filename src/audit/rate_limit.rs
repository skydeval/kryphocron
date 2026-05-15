// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.9 two-tier per-issuer rate limiter — **type-shape only**.
//!
//! The [`IssuanceRateLimiter`] struct names the four rate-limit
//! buckets the §4.3 issuance chokepoint consults. Phase 1 ships
//! the shape so [`crate::authority`] can refer to it; the
//! sharded-LRU + token-bucket runtime mechanism lands in Phase 4.

use std::time::Duration;

/// Recommended starting parameters for a [`TokenBucket`] (§4.9).
///
/// Operator-tunable.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    /// Bucket capacity.
    pub capacity: u32,
    /// Refill rate (tokens per second).
    pub refill_per_second: u32,
}

/// Two-tier per-issuer rate limiter (§4.9).
///
/// Phase 1 ships the struct shape; the
/// `ConcurrentLruCache<Did, TokenBucket>` backing the
/// recently-active per-DID tier is operator-supplied through a
/// trait surface that Phase 4 commits. See CHAINLINKS #10.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IssuanceRateLimiter {
    /// Long-tail DID bucket. Recommended: capacity 1000, refill
    /// 100/sec.
    pub long_tail_did_class: TokenBucket,
    /// Service-class bucket. Recommended: capacity 10000, refill
    /// 1000/sec.
    pub service_class: TokenBucket,
    /// Anonymous-class bucket. Recommended: capacity 1000, refill
    /// 100/sec. Sized to 10× expected sustained anonymous request
    /// rate.
    pub anonymous_class: TokenBucket,
    /// LRU cap on the recently-active-DID cache. Recommended:
    /// 10,000 entries.
    pub recently_active_did_lru_cap: usize,
}

impl Default for IssuanceRateLimiter {
    fn default() -> Self {
        IssuanceRateLimiter {
            long_tail_did_class: TokenBucket {
                capacity: 1000,
                refill_per_second: 100,
            },
            service_class: TokenBucket {
                capacity: 10_000,
                refill_per_second: 1000,
            },
            anonymous_class: TokenBucket {
                capacity: 1000,
                refill_per_second: 100,
            },
            recently_active_did_lru_cap: 10_000,
        }
    }
}

impl IssuanceRateLimiter {
    /// How long a token would take to refill from empty.
    /// Convenience for operators tuning.
    #[must_use]
    pub fn worst_case_refill(&self, b: &TokenBucket) -> Duration {
        if b.refill_per_second == 0 {
            Duration::MAX
        } else {
            Duration::from_secs(u64::from(b.capacity) / u64::from(b.refill_per_second))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_token_buckets_within_sane_bounds() {
        let r = IssuanceRateLimiter::default();
        // Sanity: service class >> long-tail >> per-DID.
        assert!(r.service_class.capacity > r.long_tail_did_class.capacity);
        assert!(r.long_tail_did_class.capacity > 0);
        assert!(r.anonymous_class.capacity > 0);
        assert_eq!(r.recently_active_did_lru_cap, 10_000);
    }
}

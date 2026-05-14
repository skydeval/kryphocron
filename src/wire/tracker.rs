//! Default in-memory [`NonceTracker`] implementation (§4.8 round-4
//! reshape).
//!
//! Operators substitute persistent / sharded backends for production.
//! [`DefaultNonceTracker`] is sized for development and single-node
//! deployments where the substrate process holds the full nonce
//! window in memory.
//!
//! Storage shape:
//!
//! - One outer `HashMap` keyed by `(NonceKind, NonceIssuerKey)` —
//!   the per-issuer-per-key partition.
//! - Each partition holds an inner `HashMap<[u8; 16], SystemTime>`
//!   recording the first-observed instant of each nonce.
//! - One `Mutex` covers the outer map. The default tracker is
//!   designed for moderate concurrency — operators with high
//!   throughput should ship a sharded or `DashMap`-backed
//!   replacement that satisfies the [`NonceTracker`] trait.
//!
//! Retention discipline (§4.8): nonces older than
//! `retention_window` are evicted lazily on insertion against the
//! partition being touched. No background-task semantics — the
//! crate does not pull in async runtime requirements for this.
//!
//! Round-4 reshape: `NonceIssuerKey = (NoncePrincipal, KeyId)`
//! partitions across signing-key rotation. A nonce bound to
//! `(principal, K1)` is in a different partition from
//! `(principal, K2)`; rotation produces a new partition without
//! invalidating replay protection in either direction.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::nonce::{
    NonceFreshness, NonceIssuerKey, NonceKind, NonceTracker, NonceTrackerError,
};

/// Default retention window for [`DefaultNonceTracker`] (§4.8).
///
/// At least `MAX_CLOCK_SKEW + max(MAX_CLAIM_VALIDITY,
/// MAX_JWT_VALIDITY)` per the §4.8 retention discipline. With the
/// recommended 30s skew, 600s claim validity, and 3600s JWT
/// validity, the lower bound is `30 + 3600 = 3630` seconds; round
/// up to one hour plus skew with extra headroom (3700s).
pub const DEFAULT_NONCE_RETENTION: Duration = Duration::from_secs(3700);

/// Per-partition cap on the number of nonces tracked in memory.
///
/// Beyond this cap, [`DefaultNonceTracker::record`] returns
/// [`NonceTrackerError::OverCapacity`] for that partition.
/// Operators with sustained per-partition throughput exceeding
/// this should ship a custom tracker.
pub const DEFAULT_PER_PARTITION_CAP: usize = 16_384;

/// In-memory [`NonceTracker`] implementation.
///
/// One [`Mutex`] covers the partition map; partition contents are
/// scanned for expired entries on every insert. Operators wanting
/// a different concurrency posture (sharded mutexes, lock-free
/// `DashMap`, persistent backend) implement [`NonceTracker`]
/// themselves.
pub struct DefaultNonceTracker {
    inner: Mutex<HashMap<(NonceKind, NonceIssuerKey), HashMap<[u8; 16], SystemTime>>>,
    retention: Duration,
    per_partition_cap: usize,
}

impl DefaultNonceTracker {
    /// Construct with [`DEFAULT_NONCE_RETENTION`] and
    /// [`DEFAULT_PER_PARTITION_CAP`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DEFAULT_NONCE_RETENTION, DEFAULT_PER_PARTITION_CAP)
    }

    /// Construct with custom retention and per-partition cap.
    /// The retention floor (`MAX_CLOCK_SKEW + max(MAX_CLAIM_VALIDITY,
    /// MAX_JWT_VALIDITY)`) is the operator's responsibility — the
    /// constructor does not validate against it because operators
    /// may legitimately use shorter retention with non-default
    /// validity ceilings.
    #[must_use]
    pub fn with_config(retention: Duration, per_partition_cap: usize) -> Self {
        DefaultNonceTracker {
            inner: Mutex::new(HashMap::new()),
            retention,
            per_partition_cap,
        }
    }
}

impl Default for DefaultNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker for DefaultNonceTracker {
    fn record(
        &self,
        kind: NonceKind,
        issuer: &NonceIssuerKey,
        nonce_bytes: &[u8; 16],
        observed_at: SystemTime,
    ) -> Result<NonceFreshness, NonceTrackerError> {
        // Mutex poisoning is treated as a backend failure — the
        // tracker's internal state is no longer trustworthy if a
        // prior caller panicked mid-update.
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| NonceTrackerError::BackendUnavailable)?;
        let key = (kind, issuer.clone());
        let partition = guard.entry(key).or_default();

        // Lazy expiry: evict entries older than retention window.
        let cutoff = observed_at
            .checked_sub(self.retention)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        partition.retain(|_, first_seen| *first_seen >= cutoff);

        // Capacity check happens after expiry so legitimate churn
        // doesn't trip the cap.
        if let Some(first_seen) = partition.get(nonce_bytes) {
            return Ok(NonceFreshness::Replay {
                first_seen_at: *first_seen,
            });
        }
        if partition.len() >= self.per_partition_cap {
            return Err(NonceTrackerError::OverCapacity);
        }
        partition.insert(*nonce_bytes, observed_at);
        Ok(NonceFreshness::Fresh)
    }

    fn retention_window(&self) -> Duration {
        self.retention
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::KeyId;
    use crate::proto::Did;
    use crate::wire::nonce::NoncePrincipal;

    fn issuer(byte: u8) -> NonceIssuerKey {
        NonceIssuerKey {
            principal: NoncePrincipal::Service(Did::new("did:plc:tracker").unwrap()),
            key_id: KeyId::from_bytes([byte; 32]),
        }
    }

    /// Default constants pinned per §4.8 retention discipline.
    #[test]
    fn defaults_meet_4_8_retention_lower_bound() {
        // §4.8: retention ≥ MAX_CLOCK_SKEW + max(MAX_CLAIM_VALIDITY,
        // MAX_JWT_VALIDITY) = 30 + max(600, 3600) = 3630s.
        assert!(DEFAULT_NONCE_RETENTION >= Duration::from_secs(3630));
    }

    /// First observation of a nonce yields `Fresh`.
    #[test]
    fn fresh_nonce_returns_fresh() {
        let t = DefaultNonceTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let r = t
            .record(NonceKind::CapabilityClaim, &issuer(1), &[0xAA; 16], now)
            .unwrap();
        assert_eq!(r, NonceFreshness::Fresh);
    }

    /// Re-observation within retention yields `Replay` with the
    /// first-seen instant intact.
    #[test]
    fn replayed_nonce_within_retention_returns_replay_with_first_seen() {
        let t = DefaultNonceTracker::new();
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        t.record(NonceKind::CapabilityClaim, &issuer(1), &[0xBB; 16], first)
            .unwrap();
        let later = first + Duration::from_secs(60);
        let r = t
            .record(NonceKind::CapabilityClaim, &issuer(1), &[0xBB; 16], later)
            .unwrap();
        assert_eq!(
            r,
            NonceFreshness::Replay {
                first_seen_at: first
            }
        );
    }

    /// Re-observation after retention expiry rolls fresh — the
    /// nonce window is bounded by design.
    #[test]
    fn replayed_nonce_after_retention_returns_fresh() {
        let t = DefaultNonceTracker::with_config(Duration::from_secs(60), 100);
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        t.record(NonceKind::CapabilityClaim, &issuer(1), &[0xCC; 16], first)
            .unwrap();
        // Past retention.
        let later = first + Duration::from_secs(120);
        let r = t
            .record(NonceKind::CapabilityClaim, &issuer(1), &[0xCC; 16], later)
            .unwrap();
        assert_eq!(r, NonceFreshness::Fresh);
    }

    /// Cross-partition isolation: the round-4 reshape's load-bearing
    /// invariant. Same nonce bytes under different `NonceIssuerKey`
    /// partitions are independent.
    #[test]
    fn same_nonce_under_different_partitions_is_independent() {
        let t = DefaultNonceTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let nonce = [0xDD; 16];

        // Different KeyId — same principal, different signing key.
        let r1 = t.record(NonceKind::CapabilityClaim, &issuer(1), &nonce, now).unwrap();
        let r2 = t.record(NonceKind::CapabilityClaim, &issuer(2), &nonce, now).unwrap();
        assert_eq!(r1, NonceFreshness::Fresh);
        assert_eq!(r2, NonceFreshness::Fresh);
    }

    /// Cross-`NonceKind` isolation: the same nonce bytes under
    /// `CapabilityClaim` vs `Jwt` are independent partitions —
    /// cross-vocabulary collisions are foreclosed.
    #[test]
    fn same_nonce_across_kinds_is_independent() {
        let t = DefaultNonceTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let nonce = [0xEE; 16];

        let r1 = t.record(NonceKind::CapabilityClaim, &issuer(1), &nonce, now).unwrap();
        let r2 = t.record(NonceKind::Jwt, &issuer(1), &nonce, now).unwrap();
        assert_eq!(r1, NonceFreshness::Fresh);
        assert_eq!(r2, NonceFreshness::Fresh);
    }

    /// Per-partition capacity returns `OverCapacity`. Exhausting
    /// the partition with distinct nonces fills the cap; the
    /// (cap+1)th distinct nonce is rejected.
    #[test]
    fn capacity_exhaustion_returns_overcapacity() {
        let t = DefaultNonceTracker::with_config(Duration::from_secs(3600), 4);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for i in 0..4u8 {
            let mut nonce = [0u8; 16];
            nonce[0] = i;
            let r = t
                .record(NonceKind::CapabilityClaim, &issuer(1), &nonce, now)
                .unwrap();
            assert_eq!(r, NonceFreshness::Fresh);
        }
        // The fifth distinct nonce exhausts the cap.
        let mut overflow = [0u8; 16];
        overflow[0] = 99;
        let err = t
            .record(NonceKind::CapabilityClaim, &issuer(1), &overflow, now)
            .unwrap_err();
        assert_eq!(err, NonceTrackerError::OverCapacity);
    }

    /// Re-observation under capacity exhaustion still surfaces
    /// `Replay` correctly — the cap is on inserts, not lookups.
    #[test]
    fn replay_check_still_works_at_capacity() {
        let t = DefaultNonceTracker::with_config(Duration::from_secs(3600), 1);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let nonce = [0xFF; 16];
        let r1 = t.record(NonceKind::CapabilityClaim, &issuer(1), &nonce, now).unwrap();
        assert_eq!(r1, NonceFreshness::Fresh);
        // Same nonce again — Replay even though partition is at
        // cap = 1.
        let r2 = t.record(NonceKind::CapabilityClaim, &issuer(1), &nonce, now).unwrap();
        assert!(matches!(r2, NonceFreshness::Replay { .. }));
    }

    /// `retention_window()` returns the configured value.
    #[test]
    fn retention_window_round_trips() {
        let t = DefaultNonceTracker::with_config(Duration::from_secs(123), 100);
        assert_eq!(t.retention_window(), Duration::from_secs(123));
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §7.5 handshake nonce tracker — trait + default in-memory
//! implementation with FIFO-bounded LRU semantics.
//!
//! Per-substrate-process, like the §4.8 capability-claim
//! [`crate::wire::NonceTracker`]. The two surfaces are
//! intentionally distinct types: the §4.8 tracker partitions by
//! `(NoncePrincipal, KeyId)` and uses lazy time-based retention;
//! the §7.5 tracker partitions by initiator [`Did`] and uses
//! FIFO-bounded LRU eviction with a 24-hour retention window.
//!
//! Storage shape (default impl):
//!
//! - One `Mutex` covers the global state.
//! - A `HashMap<(Did, [u8; 32]), SystemTime>` records membership
//!   plus first-observed instant for each (initiator, nonce) pair.
//! - A `VecDeque<(Did, [u8; 32])>` records insertion order so
//!   lazy retention sweep + cap-driven eviction are both O(amortized
//!   1) per insert.
//!
//! On insert:
//!
//! 1. Lazy retention sweep: pop entries from the front of the
//!    deque while their first-observed instant is older than
//!    `now - replay_window`.
//! 2. Membership lookup: if `(initiator, nonce)` already present,
//!    return [`crate::wire::NonceFreshness::Replay`] with the
//!    recorded `first_seen_at`.
//! 3. Cap check: if at `MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES`,
//!    evict the front of the deque (FIFO eviction; per §7.5 line
//!    6799 "a sufficiently old, infrequent nonce may be evicted
//!    before the 24-hour window expires" — replay protection
//!    degrades for evicted nonces, which is the documented cost).
//! 4. Insert into both the map and the deque; return [`Fresh`].
//!
//! Operators with federation-scale handshake volumes either ship a
//! sharded / persistent-backed tracker by implementing the trait,
//! or tighten [`MAX_HANDSHAKE_NONCE_REPLAY_WINDOW`] (per §7.5 line
//! 6809-6816).
//!
//! [`Fresh`]: crate::wire::NonceFreshness::Fresh
//! [`Did`]: crate::proto::Did

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::identity::ServiceIdentity;
use crate::proto::Did;
use crate::wire::handshake::SessionNonce;
use crate::wire::nonce::{NonceFreshness, NonceTrackerError};

/// Recommended replay-window ceiling for handshake nonces (§7.5
/// line 6781). 24 hours.
///
/// Operators may configure tighter windows via
/// [`DefaultHandshakeNonceTracker::with_config`]; the trait's
/// `replay_window()` accessor returns the value the implementation
/// chose.
pub const MAX_HANDSHAKE_NONCE_REPLAY_WINDOW: Duration =
    Duration::from_secs(24 * 3600);

/// Default-implementation memory bound for the handshake nonce
/// tracker (§7.5 line 6784).
///
/// At ~150 bytes per entry, this caps memory at ~150 MB. Sized for
/// substrates serving up to ~10,000 handshakes/hour from typical
/// federation activity without LRU eviction inside the 24-hour
/// replay window. Higher-volume operators ship custom trackers.
pub const MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES: usize = 1_000_000;

/// Asynchronous-friendly trait for §7.5 handshake nonce tracking.
///
/// `check_and_record` performs the freshness check and, on a
/// fresh nonce, records it. The default in-memory implementation
/// is [`DefaultHandshakeNonceTracker`]; operators with sharded
/// or persistent storage requirements implement the trait
/// themselves.
///
/// **Send + Sync** for use behind `Arc<dyn HandshakeNonceTracker>`
/// across substrate-internal task boundaries.
pub trait HandshakeNonceTracker: Send + Sync {
    /// Check whether the `(initiator, nonce)` pair has been seen
    /// within the replay window.
    ///
    /// Returns:
    ///
    /// - [`NonceFreshness::Fresh`] — the pair is novel; the
    ///   tracker has recorded it for the duration of the replay
    ///   window or until LRU eviction.
    /// - [`NonceFreshness::Replay`] — the pair was previously
    ///   seen at `first_seen_at`. The verifier translates this
    ///   into a `BatchRejectionReason::HandshakeNonceReplay`
    ///   rejection per §7.5.
    ///
    /// # Errors
    ///
    /// Returns [`NonceTrackerError`] for backend-internal failures
    /// (mutex poisoning, capacity exhaustion in implementations
    /// that surface that distinctly). The default implementation's
    /// FIFO eviction means it does NOT surface `OverCapacity`:
    /// the cap is enforced by eviction rather than rejection.
    fn check_and_record(
        &self,
        initiator: &ServiceIdentity,
        nonce: &SessionNonce,
        observed_at: SystemTime,
    ) -> Result<NonceFreshness, NonceTrackerError>;

    /// Replay window the tracker enforces.
    fn replay_window(&self) -> Duration;
}

/// One entry in the FIFO order log.
type FifoEntry = (Did, [u8; 32]);

/// Storage shape for the default in-memory tracker.
struct State {
    /// Membership + first-observed instant lookup.
    seen: HashMap<FifoEntry, SystemTime>,
    /// Insertion-order log for FIFO eviction + lazy retention sweep.
    order: VecDeque<FifoEntry>,
}

/// In-memory [`HandshakeNonceTracker`] implementation.
///
/// Uses a single [`Mutex`] over the storage state. The mutex covers
/// both the membership map and the FIFO order log so eviction and
/// insertion are atomic; a sharded implementation is the natural
/// next step for operators wanting more concurrency than this
/// design provides.
pub struct DefaultHandshakeNonceTracker {
    inner: Mutex<State>,
    replay_window: Duration,
    cap: usize,
}

impl DefaultHandshakeNonceTracker {
    /// Construct with [`MAX_HANDSHAKE_NONCE_REPLAY_WINDOW`] and
    /// [`MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(
            MAX_HANDSHAKE_NONCE_REPLAY_WINDOW,
            MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES,
        )
    }

    /// Construct with custom replay window and cap. Operators
    /// reducing memory may pass a tighter `cap`; operators
    /// reducing replay-window may pass a shorter `replay_window`
    /// per §7.5's "tighten replay window" guidance.
    #[must_use]
    pub fn with_config(replay_window: Duration, cap: usize) -> Self {
        DefaultHandshakeNonceTracker {
            inner: Mutex::new(State {
                seen: HashMap::new(),
                order: VecDeque::new(),
            }),
            replay_window,
            cap,
        }
    }
}

impl Default for DefaultHandshakeNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeNonceTracker for DefaultHandshakeNonceTracker {
    fn check_and_record(
        &self,
        initiator: &ServiceIdentity,
        nonce: &SessionNonce,
        observed_at: SystemTime,
    ) -> Result<NonceFreshness, NonceTrackerError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| NonceTrackerError::BackendUnavailable)?;

        // Lazy retention sweep over the FIFO log. Pop entries from
        // the front as long as their recorded first_seen is older
        // than `observed_at - replay_window`. Constant-amortized
        // cost per insert.
        let cutoff = observed_at
            .checked_sub(self.replay_window)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        while let Some(front_key) = guard.order.front() {
            let stale = matches!(
                guard.seen.get(front_key),
                Some(first_seen) if *first_seen < cutoff
            );
            if !stale {
                break;
            }
            // Stale: pop from order log AND remove from membership
            // map. Holding both atomic under the same mutex keeps
            // the two structures in lockstep.
            let evicted = guard.order.pop_front().expect("front existed");
            guard.seen.remove(&evicted);
        }

        let key: FifoEntry = (initiator.service_did().clone(), *nonce.as_bytes());

        // Membership check: if already present, return Replay with
        // the recorded first_seen_at. The lazy sweep above already
        // removed any expired entries, so any hit here is within
        // the live window.
        if let Some(first_seen) = guard.seen.get(&key) {
            return Ok(NonceFreshness::Replay {
                first_seen_at: *first_seen,
            });
        }

        // FIFO cap eviction. If at capacity, drop the front of the
        // deque (oldest by insertion order) to make room. §7.5
        // line 6799 commits this degradation: a sufficiently old,
        // infrequent nonce may be evicted before the 24-hour
        // window expires, and replay protection degrades for
        // evicted nonces. Operators sized for federation-scale
        // throughput configure custom trackers per §7.5 line
        // 6809-6816.
        if guard.seen.len() >= self.cap {
            if let Some(evicted) = guard.order.pop_front() {
                guard.seen.remove(&evicted);
            }
        }

        guard.seen.insert(key.clone(), observed_at);
        guard.order.push_back(key);
        Ok(NonceFreshness::Fresh)
    }

    fn replay_window(&self) -> Duration {
        self.replay_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{KeyId, PublicKey, SignatureAlgorithm};

    fn identity(seed: u8) -> ServiceIdentity {
        let did_str = format!("did:plc:{seed:02x}sample0000000000");
        ServiceIdentity::new_internal(
            Did::new(&did_str).unwrap(),
            KeyId::from_bytes([seed; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [seed.wrapping_add(1); 32],
            },
            None,
        )
    }

    /// Constants pinned per §7.5.
    #[test]
    fn defaults_pinned_per_7_5() {
        assert_eq!(
            MAX_HANDSHAKE_NONCE_REPLAY_WINDOW,
            Duration::from_secs(24 * 3600)
        );
        assert_eq!(MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES, 1_000_000);
    }

    /// Fresh nonce → Fresh.
    #[test]
    fn fresh_nonce_returns_fresh() {
        let t = DefaultHandshakeNonceTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let r = t
            .check_and_record(&identity(1), &SessionNonce::from_bytes([0xAA; 32]), now)
            .unwrap();
        assert_eq!(r, NonceFreshness::Fresh);
    }

    /// Re-observation within window → Replay carrying first_seen.
    #[test]
    fn replay_within_window_returns_replay() {
        let t = DefaultHandshakeNonceTracker::new();
        let id = identity(1);
        let nonce = SessionNonce::from_bytes([0xBB; 32]);
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        t.check_and_record(&id, &nonce, first).unwrap();

        let later = first + Duration::from_secs(60);
        let r = t.check_and_record(&id, &nonce, later).unwrap();
        assert_eq!(
            r,
            NonceFreshness::Replay {
                first_seen_at: first
            }
        );
    }

    /// Re-observation past replay window → Fresh (tracker expired
    /// the prior entry on the lazy sweep).
    #[test]
    fn replay_past_window_returns_fresh() {
        let t = DefaultHandshakeNonceTracker::with_config(Duration::from_secs(60), 100);
        let id = identity(1);
        let nonce = SessionNonce::from_bytes([0xCC; 32]);
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        t.check_and_record(&id, &nonce, first).unwrap();

        let later = first + Duration::from_secs(120);
        let r = t.check_and_record(&id, &nonce, later).unwrap();
        assert_eq!(r, NonceFreshness::Fresh);
    }

    /// Cross-initiator isolation: same nonce bytes from different
    /// initiators are independent.
    #[test]
    fn same_nonce_under_different_initiators_is_independent() {
        let t = DefaultHandshakeNonceTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let nonce = SessionNonce::from_bytes([0xDD; 32]);

        let r1 = t.check_and_record(&identity(1), &nonce, now).unwrap();
        let r2 = t.check_and_record(&identity(2), &nonce, now).unwrap();
        assert_eq!(r1, NonceFreshness::Fresh);
        assert_eq!(r2, NonceFreshness::Fresh);
    }

    /// Per-(initiator, key-rotation) isolation is NOT applied: the
    /// partition key is the initiator's DID, not (DID, KeyId).
    /// Same DID with different KeyId values share a partition. A
    /// federation peer rotating keys mid-handshake-window cannot
    /// replay any of its previously-used nonces under a fresh key.
    #[test]
    fn same_did_with_different_key_id_shares_partition() {
        let t = DefaultHandshakeNonceTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let nonce = SessionNonce::from_bytes([0xEE; 32]);

        let did = Did::new("did:plc:samedidsamedidsamedid").unwrap();
        let id_k1 = ServiceIdentity::new_internal(
            did.clone(),
            KeyId::from_bytes([0x01; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0x02; 32],
            },
            None,
        );
        let id_k2 = ServiceIdentity::new_internal(
            did,
            KeyId::from_bytes([0x99; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0x9A; 32],
            },
            None,
        );

        let r1 = t.check_and_record(&id_k1, &nonce, now).unwrap();
        assert_eq!(r1, NonceFreshness::Fresh);
        let r2 = t.check_and_record(&id_k2, &nonce, now).unwrap();
        assert!(
            matches!(r2, NonceFreshness::Replay { .. }),
            "same DID + same nonce must be Replay regardless of key rotation"
        );
    }

    /// FIFO eviction at cap: filling the cap then inserting one
    /// more drops the oldest entry. The just-evicted nonce shows
    /// Fresh again on re-observation (replay protection degrades,
    /// as §7.5 line 6799 commits). Non-evicted nonces remain Replay
    /// — checked before any further insertion to avoid the cascade
    /// where the next Fresh insert itself triggers another
    /// eviction.
    #[test]
    fn fifo_eviction_drops_oldest_at_cap() {
        let t = DefaultHandshakeNonceTracker::with_config(Duration::from_secs(3600), 4);
        let id = identity(1);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let nonces: [[u8; 32]; 4] = [
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0x04; 32],
        ];
        for n in &nonces {
            assert_eq!(
                t.check_and_record(&id, &SessionNonce::from_bytes(*n), now).unwrap(),
                NonceFreshness::Fresh
            );
        }

        // Fifth insert evicts the oldest ([0x01; 32]).
        let overflow = SessionNonce::from_bytes([0x05; 32]);
        assert_eq!(
            t.check_and_record(&id, &overflow, now).unwrap(),
            NonceFreshness::Fresh
        );

        // Inspect non-evicted nonces FIRST — re-observing them
        // returns Replay without triggering insertion (the fresh-
        // path side effect that would cascade additional
        // evictions). [0x02], [0x03], [0x04], [0x05] all live.
        for live in &[nonces[1], nonces[2], nonces[3], [0x05; 32]] {
            let r = t
                .check_and_record(&id, &SessionNonce::from_bytes(*live), now)
                .unwrap();
            assert!(
                matches!(r, NonceFreshness::Replay { .. }),
                "non-evicted nonce must still be Replay"
            );
        }

        // The evicted nonce ([0x01]) is now re-insertable as Fresh —
        // demonstrates the documented degradation.
        let evicted_replay = t
            .check_and_record(&id, &SessionNonce::from_bytes(nonces[0]), now)
            .unwrap();
        assert_eq!(
            evicted_replay,
            NonceFreshness::Fresh,
            "evicted nonce must be insertable again (LRU degradation)"
        );
    }

    /// `replay_window()` returns the configured value.
    #[test]
    fn replay_window_round_trips() {
        let t = DefaultHandshakeNonceTracker::with_config(Duration::from_secs(123), 100);
        assert_eq!(t.replay_window(), Duration::from_secs(123));
    }
}

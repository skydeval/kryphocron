// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.6 timing equalization.
//!
//! [`equalize_timing`] absorbs per-query latency variance across
//! the §4.3 bind pipeline by sleeping until at least a deployment-
//! configured `target` Duration has elapsed since the operation's
//! `start`. The companion helper [`equalize_timing_target_for`]
//! computes the target from a capability's declared oracle
//! consultations (sums per-oracle worst-case latencies plus
//! [`BASE_AUTHORIZATION_OVERHEAD`] and [`SAFETY_MARGIN`]).
//!
//! Together the two functions implement the §4.6 timing-channel
//! defense: an attacker observing the latency of a substrate
//! operation can sometimes infer secrets about the data or the
//! bind decision. Equalizing observed latency to a fixed floor
//! makes those inferences harder — attackers can still tell that
//! an operation took ≥ target, but can't distinguish fast-path
//! from slow-path decisions within the target window.
//!
//! §4.6 explicitly defers full constant-time discipline
//! (randomized jitter, hardened timing primitives) to v2+; v0.1
//! ships the equalization primitive and the calibration helper,
//! and assumes operators provide a target that fits their
//! deployment's threat model.

use std::time::{Duration, Instant};

use crate::authority::UserCapability;
use crate::ingress::OracleSet;

/// Base authorization overhead included in every equalization
/// budget (§4.6).
pub const BASE_AUTHORIZATION_OVERHEAD: Duration = Duration::from_millis(5);

/// Safety margin added on top of summed worst-case latencies
/// (§4.6).
pub const SAFETY_MARGIN: Duration = Duration::from_millis(2);

/// Equalize externally-observable latency to a `target` floor
/// (§4.6 timing-channel discipline).
///
/// Awaits until `start.elapsed() >= target`. If the operation
/// preceding the call already took ≥ `target`, returns
/// immediately (no negative-sleep, no spurious delay). If it
/// took less, sleeps for the remaining `target - elapsed`.
///
/// Callers compute `target` from
/// [`equalize_timing_target_for`] (sums per-oracle worst-case
/// latencies plus base + safety margin) and pass `start` as
/// the [`Instant`] captured at the beginning of the
/// security-relevant operation.
///
/// The contract is "wait until target elapsed," not "wait until
/// target elapsed OR deadline." Deadline interactions are the
/// caller's concern — wrap the equalization in a `tokio::select!`
/// against the deadline if the operation has one.
///
/// Sleep is implemented via [`tokio::time::sleep`]; operators
/// running on a non-tokio async runtime must supply a
/// tokio-compatible reactor or shim. §4.6 explicitly defers full
/// constant-time discipline (e.g., randomized jitter, hardened
/// timing primitives) to v2+; this is the equalization primitive
/// only.
pub async fn equalize_timing(start: Instant, target: Duration) {
    let elapsed = start.elapsed();
    if elapsed < target {
        tokio::time::sleep(target - elapsed).await;
    }
    // else: already past the target, return immediately.
}

/// Compute the equalization target for capability `C` against
/// the supplied oracle set (§4.6).
///
/// Sums per-query worst-case latencies from each oracle's
/// `worst_case_latency_for` over `C::ORACLE_CONSULTATIONS`,
/// then adds [`BASE_AUTHORIZATION_OVERHEAD`] and
/// [`SAFETY_MARGIN`]. Cheap queries do not inflate the budget
/// by per-oracle worst-case attribution.
#[must_use]
pub fn equalize_timing_target_for<C: UserCapability>(oracles: &OracleSet<'_>) -> Duration {
    let mut target = BASE_AUTHORIZATION_OVERHEAD;
    for query in C::ORACLE_CONSULTATIONS.block {
        target += oracles.block.worst_case_latency_for(*query);
    }
    for query in C::ORACLE_CONSULTATIONS.audience {
        target += oracles.audience.worst_case_latency_for(*query);
    }
    for query in C::ORACLE_CONSULTATIONS.mute {
        target += oracles.mute.worst_case_latency_for(*query);
    }
    target + SAFETY_MARGIN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_constants_within_sane_bounds() {
        // §4.6 commits 5ms base + 2ms safety. Sanity-pin them.
        assert_eq!(BASE_AUTHORIZATION_OVERHEAD, Duration::from_millis(5));
        assert_eq!(SAFETY_MARGIN, Duration::from_millis(2));
        // The sum should be a small but non-trivial budget.
        assert!(BASE_AUTHORIZATION_OVERHEAD + SAFETY_MARGIN < Duration::from_secs(1));
    }

    /// §4.6 happy path: an operation that completed faster than
    /// the equalization target gets padded to the target floor.
    #[tokio::test]
    async fn equalize_timing_waits_until_target_when_op_was_fast() {
        let start = Instant::now();
        let target = Duration::from_millis(50);
        equalize_timing(start, target).await;
        let observed = start.elapsed();
        // Allow ±10ms jitter for tokio::time::sleep granularity
        // on Windows/WSL where the timer wheel resolution can be
        // coarser than nominal.
        assert!(
            observed >= target,
            "equalize_timing returned at {observed:?}, before target {target:?}"
        );
        assert!(
            observed < target + Duration::from_millis(50),
            "equalize_timing slept way past target: {observed:?} vs {target:?}"
        );
    }

    /// §4.6 already-past-target path: an operation that already
    /// exceeded the target returns near-immediately, no negative-
    /// sleep, no spurious delay.
    #[tokio::test]
    async fn equalize_timing_returns_immediately_when_op_was_slow() {
        // Synthesize a `start` that's already 100ms in the past.
        let start = Instant::now() - Duration::from_millis(100);
        let target = Duration::from_millis(50);
        let call_start = Instant::now();
        equalize_timing(start, target).await;
        let call_elapsed = call_start.elapsed();
        assert!(
            call_elapsed < Duration::from_millis(10),
            "equalize_timing returned in {call_elapsed:?}; expected near-immediate return"
        );
    }

    /// §4.6 zero-target edge case: a `Duration::ZERO` target
    /// returns immediately regardless of `start`.
    #[tokio::test]
    async fn equalize_timing_handles_zero_target() {
        let start = Instant::now();
        let call_start = Instant::now();
        equalize_timing(start, Duration::ZERO).await;
        let call_elapsed = call_start.elapsed();
        assert!(
            call_elapsed < Duration::from_millis(10),
            "equalize_timing with ZERO target took {call_elapsed:?}; expected near-immediate"
        );
    }
}

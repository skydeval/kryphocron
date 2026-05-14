//! §4.6 timing equalization.
//!
//! [`equalize_timing`] wraps an async future and ensures the
//! outer observed latency is at least `target` regardless of the
//! future's actual duration. The companion helper
//! [`equalize_timing_target_for`] computes the target from a
//! capability's declared oracle consultations.
//!
//! ## Phase 1 status
//!
//! [`equalize_timing`] is a **stub** in Phase 1. The shape is
//! committed (signature, constants, calibration helper) so
//! downstream code can wire against it; the actual `pin`-and-
//! `await`-until-deadline implementation lands in Phase 4 once
//! the substrate has a chosen `Future`/`Sleep` discipline.

use std::time::Duration;

use crate::authority::UserCapability;
use crate::ingress::OracleSet;

/// Base authorization overhead included in every equalization
/// budget (§4.6).
pub const BASE_AUTHORIZATION_OVERHEAD: Duration = Duration::from_millis(5);

/// Safety margin added on top of summed worst-case latencies
/// (§4.6).
pub const SAFETY_MARGIN: Duration = Duration::from_millis(2);

/// Run `fut` and wait until at least `target` has elapsed before
/// returning its result. Used to absorb per-query latency
/// variance across the §4.3 pipeline.
///
/// **Phase 1 stub.** The signature is committed; the
/// implementation calls [`unimplemented!`]. Phase 4 wires the
/// actual sleep-until-deadline once the substrate's chosen
/// `Future` discipline is in place (§4.6, §4.10).
pub async fn equalize_timing<F, T>(_target: Duration, _fut: F) -> T
where
    F: core::future::Future<Output = T>,
{
    unimplemented!(
        "§4.6 equalize_timing: Phase 4 wires the sleep-until-deadline implementation"
    );
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
}

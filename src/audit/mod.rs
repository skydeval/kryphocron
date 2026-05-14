//! §4.9 audit pipeline + §6 audit event vocabulary.
//!
//! §4.9 commits the audit *pipeline* — four parallel channels
//! (user, channel, substrate, moderation) plus a fallback sink
//! for sink-panic and composite-failure events, per-capability
//! buffer partitioning, sink panic guards, composite-audit and
//! rollback markers. The pipeline is **type-routed** (§4.9 A2):
//! cross-class misrouting is a compile error because each
//! channel's sink takes a class-specific event enum.
//!
//! §6 commits the audit *vocabulary* — the concrete Rust enum
//! shapes that flow through the pipeline. See
//! [`crate::audit::UserAuditEvent`],
//! [`crate::audit::ChannelAuditEvent`],
//! [`crate::audit::SubstrateAuditEvent`],
//! [`crate::audit::ModerationAuditEvent`], and
//! [`crate::audit::FallbackAuditEvent`] for the per-channel
//! variant catalogs; the §6.1 cross-cutting rules (`trace_id` /
//! `at` / [`crate::TargetRepresentation`]) apply uniformly
//! across all five. The
//! [`crate::audit::UserAuditEvent`] rustdoc carries the §6.8
//! ordering tiers and §6.9 schema-evolution discipline as the
//! operator-facing source of truth.
//!
//! # Relationship between [`crate::audit::EVENT_SCHEMA_VERSION`] and the crate
//!
//! [`crate::audit::EVENT_SCHEMA_VERSION`] tracks the audit-event vocabulary on
//! a separate cadence from the crate version per §6.9. The two
//! versions are related but not equal:
//!
//! - **Schema-major bump** (variant removed, field type changed,
//!   semantics altered) **always coincides** with a crate-major
//!   bump because audit events are part of the public API.
//! - **The converse is not true:** a crate-major bump for
//!   reasons unrelated to audit events (§4.8 wire reshape, §5
//!   lexicon strategy, build-system changes) leaves
//!   `EVENT_SCHEMA_VERSION` unchanged.
//! - **Schema-minor bump** (new variant on a `#[non_exhaustive]`
//!   enum, new field on an existing variant) may coincide with
//!   any crate-version bump.
//! - **Schema-patch bump** (documentation-only change to event
//!   contracts) may coincide with any crate-version bump.
//!
//! Consumers may use [`crate::audit::EVENT_SCHEMA_VERSION`] as a coarse
//! compatibility check before parsing.

mod bounded_string;
mod composite;
mod events;
mod rate_limit;
mod sinks;

use crate::authority::predicate::SemVer;

pub use self::composite::{
    composite_audit, CompositeAuditError, CompositeAuditScope, CompositeOpId,
    CompositeRollbackMarker, TRACKER_GRACE_WINDOW_DEFAULT, TRACKER_GRACE_WINDOW_MAX,
    TRACKER_SHARDS,
};
pub use self::bounded_string::{BoundedString, BoundedStringTooLong};
pub use self::events::{
    BatchRejectionReason, ChannelAuditEvent, ChannelCloseCause, DeprecationEventDetail,
    DerivationOutcome, FallbackAuditEvent, FallbackTrustPolicy, InvalidationSource,
    ModerationAuditEvent, ModeratorRationale, NarrowingKind, OracleFreshnessState,
    PeerOperation, PeerTrustConstraints, PeerTrustDecision, RateLimitBucket,
    SubstrateAuditEvent, SyncPerspective, UserAuditEvent, MAX_RATIONALE_LEN,
};
pub use self::rate_limit::{IssuanceRateLimiter, TokenBucket};
pub use self::sinks::{
    AuditError, ChannelAuditSink, FallbackAuditSink, ModerationAuditSink, Panicked,
    SinkKind, SinkPanicGuard, SubstrateAuditSink, TerminatedSinkGuard, UserAuditSink,
};

/// Audit-event schema version (§6.9).
///
/// Tracks the audit-event vocabulary on a separate cadence from
/// the crate version. See the module-level doc on the
/// schema-vs-crate-version coupling.
///
/// `1.0.0` is the v1 contract: §6.2's user-class set, §6.3's
/// channel-class set, §6.4's substrate-class set (including the
/// §7-shaped variants whose emission paths land in Phase 4),
/// §6.5's moderation-class set, §6.6's fallback set, §6.7's
/// inspection-notification set, §6.1's cross-cutting `trace_id`
/// / `at` / [`crate::TargetRepresentation`] rules, §6.8's
/// ordering guarantees, and §6.9's evolution discipline.
pub const EVENT_SCHEMA_VERSION: SemVer = SemVer::new(1, 0, 0);

#[cfg(test)]
mod tests {
    use super::*;

    /// §6.9 commits `EVENT_SCHEMA_VERSION = SemVer::new(1, 0, 0)`
    /// for the v1 audit contract. Phase 3 ships v1; bumping this
    /// requires a coordinated crate-major bump per §6.9's
    /// schema-major-coincides-with-crate-major rule.
    #[test]
    fn event_schema_version_pinned_at_1_0_0() {
        assert_eq!(EVENT_SCHEMA_VERSION, SemVer::new(1, 0, 0));
    }
}

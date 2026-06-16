// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
//! shapes that flow through the pipeline. The four channel
//! enums plus fallback and inspection-notification:
//!
//! - [`crate::audit::UserAuditEvent`] (§6.2)
//! - [`crate::audit::ChannelAuditEvent`] (§6.3)
//! - [`crate::audit::SubstrateAuditEvent`] (§6.4)
//! - [`crate::audit::ModerationAuditEvent`] (§6.5)
//! - [`crate::audit::FallbackAuditEvent`] (§6.6)
//! - [`crate::authority::InspectionNotification`] (§6.7)
//!
//! # §6.1 cross-cutting commitments
//!
//! Three discipline rules apply uniformly to every variant in
//! every channel:
//!
//! - **Every event carries `trace_id: TraceId`.** The
//!   [`TraceId`](crate::identity::TraceId) is the cross-channel
//!   correlation key. A capability bind that emits to the user
//!   channel may correlate with a substrate-class
//!   [`crate::audit::SubstrateAuditEvent::DeprecatedWriteDuringGrace`], a
//!   [`crate::audit::UserAuditEvent::CompositeRollbackMarker`], or an
//!   [`crate::authority::InspectionNotification`] — all of which
//!   share the originating operation's `trace_id`.
//! - **Every event carries `at: SystemTime`.** The wallclock
//!   timestamp at audit-event *emission*, not at the moment the
//!   underlying action started. Cross-process correlation depends
//!   on operator clock-discipline (NTP), which the substrate does
//!   not enforce.
//! - **Subject references use [`crate::TargetRepresentation`].**
//!   Operators reading audit logs at routine privilege see the
//!   structural layer only; forensic detail requires the
//!   segregated audit-encryption key (§4.4 / §8.2). When no
//!   encryption resolver is installed (v1 default per §8.5), the
//!   sensitive layer is `None`.
//!
//! # §6.8 ordering and clock-domain reference
//!
//! `trace_id` provides set-membership across channels, **not**
//! ordering. The three guarantee tiers:
//!
//! - **Within a channel:** events appear at the sink in emission
//!   order. Each per-class buffer is a single FIFO (§4.9).
//! - **Across channels within a substrate process:** no ordering
//!   guarantee. The four sink traits are independent, with
//!   independent buffer partitions and operator-implemented
//!   backends. Two events from a single bind that emit to two
//!   different channels arrive at the respective sinks in
//!   nondeterministic order.
//! - **Across substrate processes:** operator-managed via NTP.
//!   The substrate does not enforce clock discipline.
//!
//! Some cross-channel pairs have a semantically-recoverable order
//! (e.g., a `CapabilityBound` for a grace-window write was emitted
//! *before* the `DeprecatedWriteDuringGrace` partner per §4.3's
//! pipeline order). Operators rely on this only when they have
//! substrate-knowledge of which event is causally first; it is
//! not recoverable from event content alone.
//!
//! # §6.9 schema-evolution discipline
//!
//! [`crate::audit::EVENT_SCHEMA_VERSION`] tracks the audit-event vocabulary on
//! a separate cadence from the crate version per §6.9. The two
//! versions are related but not equal:
//!
//! - **Schema-major bump** (variant removed, field type changed,
//!   semantics altered) **always coincides** with a crate-major
//!   bump because audit events are part of the public API.
//! - **The converse is not true:** a crate-major bump for reasons
//!   unrelated to audit events (§4.8 wire reshape, §5 lexicon
//!   strategy, build-system changes) leaves
//!   [`crate::audit::EVENT_SCHEMA_VERSION`] unchanged.
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
    MalformedRecordReason, ModerationAuditEvent, ModeratorRationale, NarrowingKind,
    OracleFreshnessState, PayloadCompleteness, PeerOperation, PeerTrustConstraints,
    PeerTrustDecision, RateLimitBucket, RewriteOnRotateOutcome, SubstrateAuditEvent,
    SyncPerspective, UserAuditEvent, MAX_RATIONALE_LEN,
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
/// §7-shaped variants whose emission paths land in a future
/// release), §6.5's moderation-class set, §6.6's fallback set,
/// §6.7's inspection-notification set, §6.1's cross-cutting
/// `trace_id` / `at` / [`crate::TargetRepresentation`] rules,
/// §6.8's ordering guarantees, and §6.9's evolution discipline.
pub const EVENT_SCHEMA_VERSION: SemVer = SemVer::new(1, 1, 0);

/// The substrate audit-event type names, keyed to [`EVENT_SCHEMA_VERSION`].
///
/// Consumers building audit-event filter dropdowns or vocabulary-tracking
/// surfaces read this to enumerate the current substrate event types without
/// hardcoding the list. Each entry is the fully-qualified Rust variant path
/// (`<Enum>::<Variant>`) across all five §6 audit-event enums:
/// [`UserAuditEvent`] (§6.2), [`ChannelAuditEvent`] (§6.3),
/// [`SubstrateAuditEvent`] (§6.4), [`ModerationAuditEvent`] (§6.5), and
/// [`FallbackAuditEvent`] (§6.6).
///
/// The path-qualified form is deliberate: `CompositeRollbackMarker` recurs
/// across four of the five enums, so bare variant names would collide; the
/// `<Enum>::` prefix keeps every entry unique and maps each name directly to
/// its source enum.
///
/// Grouped by enum (sink class), alphabetical within each group. Updated
/// alongside any addition to one of the five audit-event enums; the
/// exhaustive-match `*_variant_set_pinned` tests on those enums are the
/// build-time forcing function that flags drift here. Additions are a
/// schema-minor bump to [`EVENT_SCHEMA_VERSION`].
pub const AUDIT_EVENT_TYPES: &[&str] = &[
    // §6.2 user-class ([`UserAuditEvent`]).
    "UserAuditEvent::CapabilityBound",
    "UserAuditEvent::CapabilityIssuanceDenied",
    "UserAuditEvent::CompositeRollbackMarker",
    "UserAuditEvent::ContentDecodeFailed",
    "UserAuditEvent::ContentEncodeFailed",
    "UserAuditEvent::ContentEncoded",
    "UserAuditEvent::DerivedContext",
    "UserAuditEvent::ReborrowFailed",
    // §6.3 channel-class ([`ChannelAuditEvent`]).
    "ChannelAuditEvent::ChannelBound",
    "ChannelAuditEvent::ChannelClosed",
    "ChannelAuditEvent::ChannelIssuanceDenied",
    "ChannelAuditEvent::ChannelReborrowFailed",
    "ChannelAuditEvent::CompositeRollbackMarker",
    "ChannelAuditEvent::SyncBatchRejected",
    "ChannelAuditEvent::UnknownSessionMessage",
    // §6.4 substrate-class ([`SubstrateAuditEvent`]).
    "SubstrateAuditEvent::CompositeRollbackMarker",
    "SubstrateAuditEvent::DeprecatedWriteDuringGrace",
    "SubstrateAuditEvent::DidDocumentInvalidated",
    "SubstrateAuditEvent::DidDocumentRotated",
    "SubstrateAuditEvent::LexiconSetVersionChanged",
    "SubstrateAuditEvent::MalformedRecordRejected",
    "SubstrateAuditEvent::OracleFreshnessTransition",
    "SubstrateAuditEvent::PeerTrustDenied",
    "SubstrateAuditEvent::PeerTrustGranted",
    "SubstrateAuditEvent::PeerTrustUnknown",
    "SubstrateAuditEvent::RateLimitTriggered",
    "SubstrateAuditEvent::RewriteOnRotateProgress",
    "SubstrateAuditEvent::RewriteOnRotateStarted",
    "SubstrateAuditEvent::RewriteOnRotateTerminated",
    "SubstrateAuditEvent::ScopeBound",
    "SubstrateAuditEvent::ScopeIssuanceDenied",
    // §6.5 moderation-class ([`ModerationAuditEvent`]).
    "ModerationAuditEvent::CompositeRollbackMarker",
    "ModerationAuditEvent::ModerationIssuanceDenied",
    "ModerationAuditEvent::ModeratorInspected",
    "ModerationAuditEvent::ModeratorRestored",
    "ModerationAuditEvent::ModeratorTookDown",
    // §6.6 fallback-class ([`FallbackAuditEvent`]).
    "FallbackAuditEvent::CompositeFailure",
    "FallbackAuditEvent::SinkPanicked",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// §6.9: the audit-event contract is at schema `1.1.0`. The 0.3.0
    /// cycle added §8.3 codec event variants (`ContentEncoded`,
    /// `ContentEncodeFailed`, `ContentDecodeFailed`,
    /// `MalformedRecordRejected`, `RewriteOnRotate{Progress,Started,Terminated}`)
    /// — all additive on `#[non_exhaustive]` enums, hence a schema-MINOR
    /// bump (1.0.0 -> 1.1.0), which §6.9 permits alongside a crate-minor.
    #[test]
    fn event_schema_version_pinned_at_1_1_0() {
        assert_eq!(EVENT_SCHEMA_VERSION, SemVer::new(1, 1, 0));
    }

    /// `AUDIT_EVENT_TYPES` enumerates the five §6 audit-event enums' variants:
    /// User (8) + Channel (7) + Substrate (16) + Moderation (5) + Fallback (2).
    /// The count guards against a copy-paste slip in the list itself; the
    /// per-enum `*_variant_set_pinned` exhaustive-match tests in `events.rs` are
    /// the forcing function for keeping it in sync with the actual enums.
    #[test]
    fn audit_event_types_count_and_uniqueness() {
        assert_eq!(AUDIT_EVENT_TYPES.len(), 8 + 7 + 16 + 5 + 2);
        // Every entry is `<Enum>::<Variant>`-qualified, so all entries are
        // unique even though `CompositeRollbackMarker` recurs across enums.
        let mut seen = std::collections::HashSet::new();
        for name in AUDIT_EVENT_TYPES {
            assert!(name.contains("::"), "entry not enum-qualified: {name}");
            assert!(seen.insert(*name), "duplicate entry: {name}");
        }
    }
}

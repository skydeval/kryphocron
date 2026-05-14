//! §6 audit event vocabulary.
//!
//! §4.9 commits the audit *pipeline* — four-channel routing
//! (user/channel/substrate/moderation plus fallback), per-capability
//! buffer partitioning, sink panic guards, composite-audit and
//! rollback markers. §6 commits the audit *vocabulary* — the
//! concrete Rust enum shapes that flow through the pipeline.
//!
//! # §6.1 cross-cutting commitments
//!
//! Three discipline rules apply uniformly to every variant in every
//! channel:
//!
//! - **Every event carries `trace_id: TraceId`.** The
//!   [`TraceId`](crate::identity::TraceId) is the cross-channel
//!   correlation key. A capability bind that emits to the user
//!   channel may correlate with a substrate-class
//!   [`SubstrateAuditEvent::DeprecatedWriteDuringGrace`], a
//!   [`UserAuditEvent::CompositeRollbackMarker`], or an
//!   [`crate::authority::InspectionNotification`] — all of which
//!   share the originating operation's `trace_id`.
//! - **Every event carries `at: SystemTime`.** The wallclock
//!   timestamp at audit-event *emission*, not at the moment the
//!   underlying action started. Cross-process correlation depends
//!   on operator clock-discipline (NTP), which the substrate does
//!   not enforce.
//! - **Subject references use [`TargetRepresentation`].** Operators
//!   reading audit logs at routine privilege see the
//!   [`structural`](crate::target::StructuralRepresentation) layer
//!   only; forensic detail requires the segregated audit-encryption
//!   key (§4.4 / §8.2). When no encryption resolver is installed
//!   (v1 default per §8.5), the
//!   [`sensitive`](crate::target::SensitiveRepresentation) layer is
//!   `None`.
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
//! - **Across substrate processes:** operator-managed via NTP. The
//!   substrate does not enforce clock discipline.
//!
//! Some cross-channel pairs have a semantically-recoverable order
//! (e.g., a `CapabilityBound` for a grace-window write was emitted
//! *before* the `DeprecatedWriteDuringGrace` partner per §4.3's
//! pipeline order). Operators rely on this only when they have
//! substrate-knowledge of which event is causally first; it is not
//! recoverable from event content alone.
//!
//! # §6.9 schema-evolution discipline
//!
//! [`crate::audit::EVENT_SCHEMA_VERSION`] is monotonic and tracks
//! the audit-event vocabulary on a separate cadence from the crate
//! version. The operator-facing contract:
//!
//! - **Schema-major bump** (backward-incompatible event change:
//!   variant removed, field type changed, semantics altered)
//!   **always coincides** with a crate-major version bump because
//!   audit events are part of the public API. The converse is not
//!   true: a crate-major bump for unrelated reasons (§4.8 wire
//!   reshape, §5 lexicon strategy, build-system) leaves the schema
//!   version unchanged.
//! - **Schema-minor bump** (new variant on a `#[non_exhaustive]`
//!   enum, new field on an existing variant) may coincide with a
//!   crate minor or major bump.
//! - **Schema-patch bump** (documentation-only change to event
//!   contracts) may coincide with any crate-version bump.
//!
//! Consumers may use [`crate::audit::EVENT_SCHEMA_VERSION`] as a
//! coarse compatibility check before parsing.

use std::time::SystemTime;

use crate::authority::capability::CapabilityKind;
use crate::authority::predicate::{BindFailureReason, BindOutcomeRepr, DenialReason};
use crate::identity::TraceId;
use crate::ingress::{AttributionChain, Requester};
use crate::proto::Did;
use crate::target::TargetRepresentation;

use super::composite::CompositeOpId;
use super::sinks::SinkKind;

/// User-class audit events (§6.2).
///
/// Emitted to the [`crate::audit::UserAuditSink`]. One event per
/// terminal action on a user-class capability proof: issuance
/// denial at the chokepoint, terminal bind outcome, reborrow
/// failure, derivation attempt, or composite rollback marker.
///
/// All variants follow §6.1's cross-cutting rules: `trace_id`, `at`,
/// and (where applicable) [`TargetRepresentation`] for subject
/// references.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum UserAuditEvent {
    /// `authority::issue_user::<C>` rejected issuance before a proof
    /// was minted. Emitted at the chokepoint, not on bind. §6.2.
    CapabilityIssuanceDenied {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Requesting principal.
        requester: Requester,
        /// Capability that was denied.
        capability: CapabilityKind,
        /// Subject representation (§4.4).
        target_repr: TargetRepresentation,
        /// Reason the issuance chokepoint denied.
        reason: DenialReason,
        /// Attribution chain at denial; included in full per §6.2's
        /// always-include-chain semantics. Bounded depth via
        /// [`crate::MAX_CHAIN_DEPTH`].
        attribution: AttributionChain,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `UserProof::bind` ran to terminal outcome (success or
    /// failure). Exactly one of these per bind attempt; move
    /// semantics on `bind` foreclose double-emission. §6.2.
    CapabilityBound {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// User DID.
        requester: Did,
        /// Subject representation (§4.4).
        subject_repr: TargetRepresentation,
        /// Capability that was bound.
        capability: CapabilityKind,
        /// Outcome of the bind (§4.3 [`BindOutcomeRepr`]).
        outcome: BindOutcomeRepr,
        /// Attribution chain at bind; included in full per §6.2's
        /// always-include-chain semantics.
        attribution: AttributionChain,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `BoundUserProof::reborrow` failed (expired, oracle stale, or
    /// audit unavailable). Successful reborrows are silent — the
    /// original bind already emitted the terminal event. §6.2.
    ReborrowFailed {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// User DID.
        requester: Did,
        /// Subject representation (§4.4).
        subject_repr: TargetRepresentation,
        /// Capability that was reborrowed.
        capability: CapabilityKind,
        /// Reborrow-specific failure reason.
        reason: BindFailureReason,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `AuthContext::derive_for` ran to outcome. Emitted on every
    /// derivation attempt (success and failure). §6.2.
    DerivedContext {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Source requester before derivation.
        from: Requester,
        /// Target requester after derivation.
        to: Requester,
        /// Discriminator for which `derive_for` variant ran.
        narrowing_kind: NarrowingKind,
        /// Derivation outcome.
        outcome: DerivationOutcome,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Composite-audit rollback marker. Emitted to every user sink
    /// that already committed within a `composite_audit` scope when
    /// a sibling sink failed; validates against the process-local
    /// [`CompositeOpId`] tracker (§4.9). §6.2.
    CompositeRollbackMarker {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Identifies the composite scope this marker rolls back.
        composite_op_id: CompositeOpId,
        /// Which sibling sink's failure triggered the rollback.
        failing_sink: SinkKind,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
}

/// Channel-class audit events (Phase 3 fills in the variant set
/// per §6). Phase 1 carries a single placeholder event so the
/// type is constructible from tests.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ChannelAuditEvent {
    /// Capability proof bound on a channel-class operation.
    CapabilityBound {
        /// Trace id.
        trace_id: TraceId,
        /// Capability.
        capability: CapabilityKind,
        /// Outcome.
        outcome: BindOutcomeRepr,
        /// When.
        at: SystemTime,
    },
}

/// Substrate-class audit events.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SubstrateAuditEvent {
    /// Substrate capability bound.
    CapabilityBound {
        /// Trace id.
        trace_id: TraceId,
        /// Capability.
        capability: CapabilityKind,
        /// Outcome.
        outcome: BindOutcomeRepr,
        /// When.
        at: SystemTime,
    },
}

/// Moderation-class audit events.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ModerationAuditEvent {
    /// Moderation capability bound.
    CapabilityBound {
        /// Trace id.
        trace_id: TraceId,
        /// Capability.
        capability: CapabilityKind,
        /// Outcome.
        outcome: BindOutcomeRepr,
        /// When.
        at: SystemTime,
    },
}

/// Fallback event vocabulary — what
/// [`crate::audit::FallbackAuditSink`] receives (§4.9).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum FallbackAuditEvent {
    /// Sink panicked.
    SinkPanic {
        /// Which sink.
        sink: SinkKind,
        /// Trace id.
        trace_id: TraceId,
        /// Capability that was being recorded.
        capability: CapabilityKind,
    },
    /// Composite-audit failure.
    CompositeFailure {
        /// Trace id.
        trace_id: TraceId,
        /// Composite op id.
        composite_op_id: CompositeOpId,
        /// Sinks that committed before the failure.
        sinks_committed: Vec<SinkKind>,
        /// Sinks that failed.
        sinks_failed: Vec<SinkKind>,
    },
}

/// Discriminator for [`UserAuditEvent::DerivedContext`] events
/// (§6.2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NarrowingKind {
    /// `derive_for(ToAnonymous)`.
    ToAnonymous,
    /// `derive_for(NarrowCapabilities)`.
    NarrowCapabilities,
    /// `derive_for(ServiceToService)`.
    ServiceToService,
}

/// Outcome of an `AuthContext::derive_for` attempt (§6.2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerivationOutcome {
    /// Derivation succeeded.
    Success,
    /// Chain depth exceeded.
    ChainTooDeep,
    /// Narrowing was structurally illegal.
    IllegalNarrowing,
    /// Service-to-service requested without declaration.
    UndeclaredServiceTrust,
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::authority::capability::CapabilityKind;
    use crate::authority::predicate::{BindFailureReason, BindOutcomeRepr, DenialReason};
    use crate::identity::TraceId;
    use crate::ingress::{AttributionChain, Requester};
    use crate::oracle::{OracleKind, OracleQueryKind, BlockOracleQuery};
    use crate::proto::Did;
    use crate::target::{StructuralRepresentation, TargetRepresentation};

    fn sample_did() -> Did {
        Did::new("did:plc:phase3test").unwrap()
    }

    fn sample_target_repr() -> TargetRepresentation {
        TargetRepresentation::structural_only(StructuralRepresentation::Resource {
            did: sample_did(),
            nsid: crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
        })
    }

    fn sample_trace_id() -> TraceId {
        TraceId::from_bytes([0u8; 16])
    }

    /// §6.2 commits exactly five variants in this order:
    /// `CapabilityIssuanceDenied`, `CapabilityBound`,
    /// `ReborrowFailed`, `DerivedContext`, `CompositeRollbackMarker`.
    /// The exhaustive match (no wildcard) makes adding/removing a
    /// variant a compile error — the intended forcing function
    /// against silent vocabulary drift.
    #[test]
    fn user_audit_event_v1_variant_set_pinned() {
        let trace_id = sample_trace_id();
        let at = SystemTime::UNIX_EPOCH;
        let cap = CapabilityKind::ViewPrivate;
        let target = sample_target_repr();

        let denied = UserAuditEvent::CapabilityIssuanceDenied {
            trace_id,
            requester: Requester::Anonymous,
            capability: cap,
            target_repr: target.clone(),
            reason: DenialReason::OwnershipCheckFailed,
            attribution: AttributionChain::empty(),
            at,
        };
        let bound = UserAuditEvent::CapabilityBound {
            trace_id,
            requester: sample_did(),
            subject_repr: target.clone(),
            capability: cap,
            outcome: BindOutcomeRepr::Success,
            attribution: AttributionChain::empty(),
            at,
        };
        let reborrow = UserAuditEvent::ReborrowFailed {
            trace_id,
            requester: sample_did(),
            subject_repr: target,
            capability: cap,
            reason: BindFailureReason::OracleStale {
                oracle: OracleKind::Block,
                query: OracleQueryKind::Block(
                    BlockOracleQuery::RequesterVsResourceOwner,
                ),
            },
            at,
        };
        let derived = UserAuditEvent::DerivedContext {
            trace_id,
            from: Requester::Did(sample_did()),
            to: Requester::Anonymous,
            narrowing_kind: NarrowingKind::ToAnonymous,
            outcome: DerivationOutcome::Success,
            at,
        };
        let rollback = UserAuditEvent::CompositeRollbackMarker {
            trace_id,
            composite_op_id: CompositeOpId::from_bytes([0u8; 16]),
            failing_sink: SinkKind::Channel,
            at,
        };

        for ev in [denied, bound, reborrow, derived, rollback] {
            match ev {
                UserAuditEvent::CapabilityIssuanceDenied { .. }
                | UserAuditEvent::CapabilityBound { .. }
                | UserAuditEvent::ReborrowFailed { .. }
                | UserAuditEvent::DerivedContext { .. }
                | UserAuditEvent::CompositeRollbackMarker { .. } => {}
            }
        }
    }

    /// §6.1 commits `trace_id` and `at` on every variant. Smoke
    /// test: extract both fields from each variant and confirm they
    /// match what was constructed.
    #[test]
    fn user_audit_event_carries_trace_id_and_at_per_6_1() {
        let trace_id = sample_trace_id();
        let at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123);
        let bound = UserAuditEvent::CapabilityBound {
            trace_id,
            requester: sample_did(),
            subject_repr: sample_target_repr(),
            capability: CapabilityKind::ViewPrivate,
            outcome: BindOutcomeRepr::Success,
            attribution: AttributionChain::empty(),
            at,
        };
        let UserAuditEvent::CapabilityBound { trace_id: t, at: a, .. } = &bound else {
            panic!("expected CapabilityBound");
        };
        assert_eq!(*t, trace_id);
        assert_eq!(*a, at);
    }

    /// §6.2 promises `attribution: AttributionChain` on
    /// `CapabilityIssuanceDenied` and `CapabilityBound`.
    #[test]
    fn user_audit_event_attribution_chain_present_on_denial_and_bind() {
        let chain = AttributionChain::empty();
        let _denied = UserAuditEvent::CapabilityIssuanceDenied {
            trace_id: sample_trace_id(),
            requester: Requester::Anonymous,
            capability: CapabilityKind::ViewPrivate,
            target_repr: sample_target_repr(),
            reason: DenialReason::OwnershipCheckFailed,
            attribution: chain.clone(),
            at: SystemTime::UNIX_EPOCH,
        };
        let _bound = UserAuditEvent::CapabilityBound {
            trace_id: sample_trace_id(),
            requester: sample_did(),
            subject_repr: sample_target_repr(),
            capability: CapabilityKind::ViewPrivate,
            outcome: BindOutcomeRepr::Success,
            attribution: chain,
            at: SystemTime::UNIX_EPOCH,
        };
    }
}

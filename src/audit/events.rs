//! §4.9 audit event vocabulary — Phase 1 shapes the four parallel
//! channel enums plus the fallback event vocabulary.
//!
//! Phase 3 (§6) revises and completes the variant set.

use std::time::SystemTime;

use crate::authority::capability::CapabilityKind;
use crate::authority::predicate::{BindFailureReason, BindOutcomeRepr, DenialReason};
use crate::identity::TraceId;
use crate::ingress::{AttributionChain, Requester};
use crate::proto::Did;
use crate::target::TargetRepresentation;

use super::composite::CompositeOpId;
use super::sinks::SinkKind;

/// User-class audit events (§4.9).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum UserAuditEvent {
    /// Capability issuance denied at the §4.3 chokepoint.
    CapabilityIssuanceDenied {
        /// Forensic trace id.
        trace_id: TraceId,
        /// Requesting principal.
        requester: Requester,
        /// Capability that was denied.
        capability: CapabilityKind,
        /// Subject representation.
        target_repr: TargetRepresentation,
        /// Why.
        reason: DenialReason,
        /// Attribution chain at denial.
        attribution: AttributionChain,
        /// When.
        at: SystemTime,
    },
    /// Capability proof binding completed (success or failure).
    CapabilityBound {
        /// Forensic trace id.
        trace_id: TraceId,
        /// User DID.
        requester: Did,
        /// Subject representation.
        subject_repr: TargetRepresentation,
        /// Capability that was bound.
        capability: CapabilityKind,
        /// Outcome of the bind.
        outcome: BindOutcomeRepr,
        /// Attribution chain.
        attribution: AttributionChain,
        /// When.
        at: SystemTime,
    },
    /// Reborrow of an already-bound proof failed.
    ReborrowFailed {
        /// Forensic trace id.
        trace_id: TraceId,
        /// User DID.
        requester: Did,
        /// Subject representation.
        subject_repr: TargetRepresentation,
        /// Capability that was reborrowed.
        capability: CapabilityKind,
        /// Reason.
        reason: BindFailureReason,
        /// When.
        at: SystemTime,
    },
    /// `AuthContext::derive_for` attempt.
    DerivedContext {
        /// Forensic trace id.
        trace_id: TraceId,
        /// Source requester.
        from: Requester,
        /// Target requester.
        to: Requester,
        /// Narrowing kind.
        narrowing_kind: NarrowingKind,
        /// Outcome.
        outcome: DerivationOutcome,
        /// When.
        at: SystemTime,
    },
    /// Composite-audit rollback marker.
    CompositeRollbackMarker {
        /// Forensic trace id.
        trace_id: TraceId,
        /// Composite op id.
        composite_op_id: CompositeOpId,
        /// Failing sink.
        failing_sink: SinkKind,
        /// When.
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

/// Discriminator for `DerivedContext` events (§4.9).
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

/// Outcome of an `AuthContext::derive_for` attempt (§4.9).
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

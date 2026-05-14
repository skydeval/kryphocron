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

use std::time::{Duration, SystemTime};

use crate::authority::capability::CapabilityKind;
use crate::authority::predicate::{BindFailureReason, BindOutcomeRepr, DenialReason, SemVer};
use crate::authority::ModerationCaseId;
use crate::identity::{KeyId, ServiceIdentity, SessionDigest, SessionId, TraceId};
use crate::ingress::{AttributionChain, Requester};
use crate::oracle::OracleKind;
use crate::proto::{Did, Nsid};
use crate::resolver::PeerKind;
use crate::target::TargetRepresentation;

use super::bounded_string::BoundedString;
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

/// Channel-class audit events (§6.3).
///
/// Emitted to the [`crate::audit::ChannelAuditSink`]. Channels are
/// sync-channel sessions between substrate peers (§4.3
/// [`crate::Endpoint`]); these variants record session lifecycle
/// and per-session activity. `session_digest` is the keyed-Blake3
/// hash of the session id (§4.4), correlating multiple events from
/// the same session within the deployment without leaking session
/// identity across deployments.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ChannelAuditEvent {
    /// `ChannelProof::bind` ran to terminal outcome. Establishes a
    /// session-bound proof for the sync channel. §6.3.
    ChannelBound {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Keyed-Blake3 session digest (§4.4).
        session_digest: SessionDigest,
        /// Channel-class endpoint capability.
        endpoint: CapabilityKind,
        /// Outcome of the bind (§4.3 [`BindOutcomeRepr`]).
        outcome: BindOutcomeRepr,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Channel issuance was rejected at the authority chokepoint.
    /// §6.3.
    ChannelIssuanceDenied {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Channel-class endpoint capability.
        endpoint: CapabilityKind,
        /// Reason the issuance chokepoint denied.
        reason: DenialReason,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// A reborrow of a bound channel proof failed mid-session.
    /// Successful reborrows are silent (the original bind covered
    /// the terminal event). §6.3.
    ChannelReborrowFailed {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Keyed-Blake3 session digest.
        session_digest: SessionDigest,
        /// Channel-class endpoint capability.
        endpoint: CapabilityKind,
        /// Reborrow-specific failure reason.
        reason: BindFailureReason,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// A sync batch was rejected wholesale (e.g., lexicon-set
    /// version skew detected at handshake per §5.5). Per-record
    /// rejections during a successful sync emit individual user-
    /// or substrate-class events; this variant is for whole-batch
    /// rejections. §6.3.
    ///
    /// Emitted symmetrically: the substrate that observes the
    /// rejection emits one event from its perspective. The
    /// rejecting side and the rejected side both emit (when their
    /// observation paths allow it; §7's sync-handshake spec
    /// commits to the receiver sending a rejection signal before
    /// closing so the sender observes the rejection rather than
    /// just timing out). Round-1 patch F4 introduced
    /// [`SyncPerspective`] to disambiguate.
    SyncBatchRejected {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Keyed-Blake3 session digest.
        session_digest: SessionDigest,
        /// Whether this substrate was the local sender or
        /// receiver in the rejected sync.
        perspective: SyncPerspective,
        /// Reason for the batch rejection.
        reason: BatchRejectionReason,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Channel session ended. The substrate emits one per session
    /// regardless of cause (clean close, peer disconnect, timeout,
    /// substrate shutdown). §6.3.
    ChannelClosed {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Keyed-Blake3 session digest.
        session_digest: SessionDigest,
        /// What ended the session.
        cause: ChannelCloseCause,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// A sync-channel message arrived with a `session_id` not in
    /// the receiving substrate instance's local session tracker.
    /// Typically indicates load-balancer routing misconfiguration
    /// in multi-instance deployments (sessions are process-local
    /// per §7.5; sticky load-balancing is required for handshake-
    /// established sessions). The substrate closes the connection
    /// after emitting this event; operators monitoring for this
    /// event detect routing anomalies. §6.3.
    UnknownSessionMessage {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// The session id observed on the wire.
        session_id_received: SessionId,
        /// Peer identity, if any portion of the handshake
        /// completed before the unknown-session-id failure.
        peer_identity: Option<ServiceIdentity>,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Composite-audit rollback marker for channel-class
    /// operations. §6.3.
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

/// Discriminator for [`ChannelAuditEvent::SyncBatchRejected`]'s
/// `perspective` field (§6.3, round-1 patch F4).
///
/// The two-perspective variant set distinguishes whether *this*
/// substrate was the sender or receiver in the rejected sync, so
/// operators correlating sender-side and receiver-side records of
/// the same rejection can recover causality.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncPerspective {
    /// This substrate initiated the sync; the rejection was
    /// observed from the peer or via timeout.
    LocalAsSender,
    /// The peer initiated the sync; this substrate rejected it.
    LocalAsReceiver,
}

/// Reason a sync batch was rejected wholesale (§6.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchRejectionReason {
    /// Lexicon-set major versions did not match across peers.
    /// Round-1 patch on §5.5 made the major version a hard
    /// rejection criterion at the handshake stage.
    LexiconSetMajorVersionMismatch {
        /// This substrate's local lexicon-set version.
        local: SemVer,
        /// Peer's lexicon-set version as observed at handshake.
        peer: SemVer,
    },
    /// Peer not present in the local trust set.
    UnauthorizedPeer,
    /// Handshake signature did not verify under the peer's
    /// declared key material.
    HandshakeSignatureInvalid,
    /// Handshake did not complete within its timeout.
    HandshakeTimeout,
    /// Handshake nonce was previously seen; replay rejected.
    HandshakeNonceReplay {
        /// `at` of the first observation of this nonce.
        first_seen_at: SystemTime,
    },
}

/// What ended a channel session (§6.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelCloseCause {
    /// Both peers concluded the session via the protocol's clean-
    /// close handshake.
    CleanClose,
    /// Peer disconnected without a clean-close handshake.
    PeerDisconnected,
    /// Session exceeded its activity timeout.
    Timeout,
    /// Substrate process is shutting down; sessions closed as
    /// part of orderly drain.
    SubstrateShutdown,
    /// A protocol-level error closed the session. Free-text
    /// `detail` is operator-visible.
    ProtocolError {
        /// Operator-visible static rationale string.
        detail: &'static str,
    },
}

/// Substrate-class audit events (§6.4).
///
/// Emitted to the [`crate::audit::SubstrateAuditSink`]. Records
/// substrate-internal operations: scope-bound capability use
/// (shard scans, replication, garbage collection), lexicon-set
/// lifecycle, deprecation policy enforcement, oracle state
/// transitions, and (under §7's federation surface) DID-document
/// rotation/invalidation and peer-trust resolution outcomes.
///
/// The §7-shaped variants ship in Phase 3 with placeholder field
/// types (`PeerOperation`, `PeerTrustConstraints`,
/// `FallbackTrustPolicy`, `PeerTrustDecision`) per the kickoff's
/// stub-now-fill-later pattern. §7.7 (Phase 4) lands the
/// federation-side wire-format implementations that produce these
/// events; the audit-event variant *shapes* committed by §6.4 do
/// not change.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SubstrateAuditEvent {
    /// `SubstrateProof::bind` ran to terminal outcome. §6.4.
    ScopeBound {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Service principal that bound the scope.
        service: ServiceIdentity,
        /// Subject representation for the scope (§4.4
        /// [`crate::ScopeKind`] backs the structural layer).
        scope_repr: TargetRepresentation,
        /// Substrate-class capability that was bound.
        capability: CapabilityKind,
        /// Outcome of the bind (§4.3 [`BindOutcomeRepr`]).
        outcome: BindOutcomeRepr,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Substrate-class issuance denied at the chokepoint. §6.4.
    ScopeIssuanceDenied {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Service principal whose issuance was denied.
        service: ServiceIdentity,
        /// Substrate-class capability that was denied.
        capability: CapabilityKind,
        /// Reason the issuance chokepoint denied.
        reason: DenialReason,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Lexicon set version changed between substrate restarts.
    /// Emitted once at startup after detecting the change against
    /// the running substrate's compiled-in registry. §6.4.
    LexiconSetVersionChanged {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Lexicon-set version observed by the previous substrate
        /// process.
        from_version: SemVer,
        /// Lexicon-set version this substrate process loaded.
        to_version: SemVer,
        /// Per-NSID deprecation events introduced by the upgrade.
        deprecations: Vec<DeprecationEventDetail>,
        /// New NSIDs added by the upgrade.
        additions: Vec<Nsid>,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// A write to a deprecated NSID was admitted during its grace
    /// window. Stage-0 of the §4.3 pipeline emits this when
    /// `DeprecationState::DeprecatedWithGrace { grace_until, .. }`
    /// applies and `now < grace_until`. The corresponding
    /// [`UserAuditEvent::CapabilityBound`] records the bind itself
    /// as `Success`; this event records the substrate-policy
    /// observation. §6.4.
    DeprecatedWriteDuringGrace {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Deprecated NSID written to.
        nsid: &'static str,
        /// Capability under which the write was admitted.
        capability: CapabilityKind,
        /// Requesting user.
        requester: Did,
        /// Lexicon-set version at which deprecation took effect.
        since_version: SemVer,
        /// `SystemTime` past which writes to `nsid` will be
        /// rejected.
        grace_until: SystemTime,
        /// Successor NSID, if one is committed.
        successor: Option<&'static str>,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Oracle freshness transitioned from acceptable to stale, or
    /// vice versa. §6.4.
    ///
    /// **Best-effort observation event** (round-1 patch F3): the
    /// substrate may coalesce rapid transitions (e.g., a flapping
    /// oracle oscillating around its freshness bound). Operators
    /// relying on precise oracle-health observation should consult
    /// external oracle-health metrics; this event is for rough
    /// operational visibility, not precise edge-detection.
    OracleFreshnessTransition {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Which oracle.
        oracle: OracleKind,
        /// State immediately before the transition.
        from_state: OracleFreshnessState,
        /// State immediately after the transition.
        to_state: OracleFreshnessState,
        /// Age of the oracle's data at the moment of transition.
        sync_age: Duration,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Issuance rate limit triggered, denying a request that would
    /// otherwise have proceeded. Per-Did and per-class bucket
    /// exhaustions both emit this; the `bucket` field
    /// disambiguates. §6.4.
    RateLimitTriggered {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Requesting principal.
        requester: Requester,
        /// Which rate-limit bucket exhausted.
        bucket: RateLimitBucket,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Composite-audit rollback marker for substrate-class
    /// operations. §6.4.
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

    // ──────── §7 inter-service auth events ────────
    //
    // Variants below ship in Phase 3 per §6.4. Their event-emission
    // *paths* are wired in Phase 4 alongside §7's full inter-service
    // auth implementation. Phase 3 ships the variant shapes so
    // audit-tooling consumers see the §6.4-committed surface; the
    // placeholder field types (`PeerOperation`, `InvalidationSource`,
    // `FallbackTrustPolicy`, `PeerTrustDecision`,
    // `PeerTrustConstraints`) are minimal v1 shells and Phase 4 may
    // refine them — see chainlinks for migration notes.
    /// DID document for a verified principal changed between
    /// cache-loaded and current resolution. §7.3 / §6.4.
    DidDocumentRotated {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Principal whose document rotated.
        did: Did,
        /// Verification-method key ids on the prior document.
        previous_methods: Vec<KeyId>,
        /// Verification-method key ids on the current document.
        current_methods: Vec<KeyId>,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Cached DID document was invalidated (operator-initiated or
    /// substrate-initiated). §7.3 / §6.4.
    DidDocumentInvalidated {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Principal whose cached document was invalidated.
        did: Did,
        /// Source that triggered the invalidation.
        invalidated_by: InvalidationSource,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `PeerTrustResolver` returned `Trusted` or
    /// `TrustedWithConstraints` for an operation. The `kind` field
    /// records the operator-declared peer kind, which drives
    /// substrate-side default behaviors (e.g., the
    /// `DEFAULT_FEDERATION_TIME_WINDOW` ceiling applies only to
    /// `Federation`). §7.7 / §6.4.
    PeerTrustGranted {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Operation the trust query was about.
        operation: PeerOperation,
        /// Operator-declared peer kind ([`PeerKind`]; reused from
        /// `crate::resolver`).
        kind: PeerKind,
        /// Constraints attached to a constrained-trust grant, or
        /// `None` for an unconstrained grant.
        constraints: Option<PeerTrustConstraints>,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `PeerTrustResolver` returned `Distrusted` for an operation.
    /// §7.7 / §6.4.
    PeerTrustDenied {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Operation the trust query was about.
        operation: PeerOperation,
        /// Operator-visible static rationale string.
        reason: &'static str,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `PeerTrustResolver` returned `Unknown`; fallback policy
    /// applied. The `interim_decision_applied` field records what
    /// the substrate did with the operation while
    /// `FallbackTrustPolicy::PromptOperator` waited for operator
    /// response (for other fallback variants, the field reflects
    /// the policy's automatic decision). §7.7 / §6.4.
    PeerTrustUnknown {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Peer service identity.
        peer: ServiceIdentity,
        /// Operation the trust query was about.
        operation: PeerOperation,
        /// Fallback policy the substrate consulted.
        fallback_applied: FallbackTrustPolicy,
        /// Decision the substrate applied to the operation in the
        /// interim.
        interim_decision_applied: PeerTrustDecision,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
}

/// Per-NSID detail of a deprecation event in
/// [`SubstrateAuditEvent::LexiconSetVersionChanged`] (§6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeprecationEventDetail {
    /// NSID that became deprecated at the upgrade.
    pub nsid: Nsid,
    /// Lexicon-set version at which deprecation took effect.
    pub since_version: SemVer,
    /// Successor NSID, if a successor was declared.
    pub successor: Option<Nsid>,
}

/// Oracle-freshness state for
/// [`SubstrateAuditEvent::OracleFreshnessTransition`] (§6.4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleFreshnessState {
    /// Oracle is within its `data_freshness_bound`.
    Fresh,
    /// Oracle is past its `data_freshness_bound`. The amount by
    /// which the bound is exceeded helps operators distinguish
    /// brief drift from sustained outage.
    Stale {
        /// How far past the freshness bound the oracle is.
        exceeded_bound_by: Duration,
    },
}

/// Rate-limit bucket identifier for
/// [`SubstrateAuditEvent::RateLimitTriggered`] (§6.4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitBucket {
    /// Per-DID active-bucket exhaustion (recently-active LRU tier
    /// per §4.9).
    PerDidActive,
    /// Long-tail per-DID class-bucket exhaustion.
    LongTailDidClass,
    /// Service-class bucket exhaustion.
    ServiceClass,
    /// Anonymous-class bucket exhaustion. Per §6.11, this is a
    /// capacity signal, not an attribution signal — anonymous
    /// requesters carry no per-source identifier.
    AnonymousClass,
}

/// Source of a DID-document invalidation in
/// [`SubstrateAuditEvent::DidDocumentInvalidated`] (§6.4).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationSource {
    /// Operator invoked `DidResolver::invalidate` via admin
    /// tooling.
    Operator,
    /// Substrate invalidated proactively (e.g., on detected
    /// rotation, on `Tombstoned` resolution).
    Substrate {
        /// Operator-visible static rationale string.
        reason: &'static str,
    },
}

// ============================================================
// §7-shaped placeholder types for §6.4 audit-event payloads.
// ============================================================
//
// §6.4 references `PeerOperation`, `PeerTrustConstraints`,
// `FallbackTrustPolicy`, and `PeerTrustDecision`. None of these
// exist in Phase 1's `crate::resolver` — Phase 1 ships the older
// `TrustOperation` / `TrustDecision` shapes that §7 will replace.
// Phase 3 ships the §6.4-named types as `#[non_exhaustive]`
// minimal-v1 shells so the audit-event surface is constructible
// today; Phase 4's §7.7 implementation either keeps these shapes,
// extends them, or reconciles with new resolver-side types.
// Chainlinks track the reconciliation work.

/// What cross-peer operation a [`SubstrateAuditEvent::PeerTrustGranted`]
/// / [`SubstrateAuditEvent::PeerTrustDenied`] /
/// [`SubstrateAuditEvent::PeerTrustUnknown`] is about (§7.7).
///
/// Phase 3 ships v1 with the same three operations
/// [`crate::resolver::TrustOperation`] enumerates. Phase 4 may
/// refine or extend.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerOperation {
    /// Accept a sync-channel handshake from this peer.
    AcceptSyncHandshake,
    /// Accept a capability claim issued by this peer.
    AcceptCapabilityClaim,
    /// Replicate a record from this peer.
    ReplicateRecord,
}

/// Constraints attached to a `TrustedWithConstraints` peer-trust
/// grant (§7.7).
///
/// Phase 3 ships an empty `#[non_exhaustive]` shell so
/// [`SubstrateAuditEvent::PeerTrustGranted`]'s `constraints:
/// Option<PeerTrustConstraints>` field is constructible. Phase 4
/// commits the constraint vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PeerTrustConstraints {}

/// Operator-configured fallback policy applied when a trust query
/// returns `Unknown` (§7.7 / §6.4).
///
/// Phase 3 ships v1 with three variants; the spec at §6.4
/// explicitly mentions `PromptOperator`. Phase 4 may extend.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FallbackTrustPolicy {
    /// Prompt the operator and hold the operation pending the
    /// response (§6.4).
    PromptOperator,
    /// Deny the operation by default.
    DefaultDeny,
    /// Allow the operation by default.
    DefaultAllow,
}

/// Decision the substrate applied to a peer-trust query in the
/// interim while a fallback policy resolved (§7.7 / §6.4).
///
/// Phase 3 ships v1 with three variants. Phase 4 may refine.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerTrustDecision {
    /// Operation was allowed.
    Accept,
    /// Operation was denied.
    Reject,
    /// Operation was held pending an operator decision.
    Deferred,
}

/// Moderation-class audit events (§6.5).
///
/// Emitted to the [`crate::audit::ModerationAuditSink`]. Records
/// moderator capability use; pair with
/// [`crate::authority::InspectionNotification`] events (§6.7) for
/// forward-attributed notifications to affected resource owners
/// via shared `trace_id`.
///
/// All variants follow §6.1's cross-cutting rules. Variants
/// recording moderator decisions carry a
/// [`ModeratorRationale`]; round-1 patch F2 introduced the
/// [`MAX_RATIONALE_LEN`] = 4096 byte bound, validated at
/// `CapabilityClaim` construction (§4.8 pattern) rather than at
/// audit-emit time.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ModerationAuditEvent {
    /// `ModeratorRead` bind. The substrate emits ONE event here
    /// AND ONE inspection notification (§6.7) per bind. Both
    /// share `trace_id`. §6.5.
    ModeratorInspected {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Moderator DID.
        moderator: Did,
        /// Moderation case identifier.
        case: ModerationCaseId,
        /// Subject representation (§4.4).
        target_repr: TargetRepresentation,
        /// Moderator-declared rationale (length-bounded per
        /// round-1 patch F2).
        rationale: ModeratorRationale,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `ModeratorTakedown` bind ran to terminal outcome. §6.5.
    ModeratorTookDown {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Moderator DID.
        moderator: Did,
        /// Moderation case identifier.
        case: ModerationCaseId,
        /// Subject representation (§4.4).
        target_repr: TargetRepresentation,
        /// Outcome of the bind (§4.3 [`BindOutcomeRepr`]).
        outcome: BindOutcomeRepr,
        /// Moderator-declared rationale.
        rationale: ModeratorRationale,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// `ModeratorRestore` bind ran to terminal outcome. The
    /// inverse of takedown; restores `RecordState::TakenDown`
    /// records to `Live`. §6.5.
    ModeratorRestored {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Moderator DID.
        moderator: Did,
        /// Moderation case identifier.
        case: ModerationCaseId,
        /// Subject representation (§4.4).
        target_repr: TargetRepresentation,
        /// Outcome of the bind (§4.3 [`BindOutcomeRepr`]).
        outcome: BindOutcomeRepr,
        /// Moderator-declared rationale.
        rationale: ModeratorRationale,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Moderation-class issuance was rejected at the chokepoint.
    /// §6.5.
    ModerationIssuanceDenied {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Moderator DID.
        moderator: Did,
        /// Moderation-class capability that was denied.
        capability: CapabilityKind,
        /// Reason the issuance chokepoint denied.
        reason: DenialReason,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// Composite-audit rollback marker for moderation-class
    /// operations. §6.5.
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

/// Moderator-declared rationale for a moderation action (§6.5).
///
/// Required for all moderation-class capabilities. The substrate
/// does not enforce content of the string but does enforce length
/// and presence per round-1 patch F2 — see [`MAX_RATIONALE_LEN`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeratorRationale {
    /// Free-text rationale field on the capability claim, declared
    /// by the moderator at issuance time.
    Declared(BoundedString<MAX_RATIONALE_LEN>),
}

/// Maximum byte length of a [`ModeratorRationale::Declared`]
/// payload (§6.5 round-1 patch F2).
///
/// 4 KB is the v1 cap; matches "generous free-text prose,
/// structured rationale references go out-of-band." Raising the
/// bound in a future version is additive within the
/// `#[non_exhaustive]` discipline.
pub const MAX_RATIONALE_LEN: usize = 4096;

/// Fallback channel events (§6.6).
///
/// Emitted to the [`crate::audit::FallbackAuditSink`]. Reserved for
/// emission failures in the four primary channels; operators route
/// fallback events to out-of-band channels (stderr, syslog) so they
/// survive primary pipeline failure.
///
/// Fallback events have a deliberately minimal field set; the
/// channel exists for the case where the primary channel can't be
/// trusted. Forensic detail comes from correlating `trace_id` with
/// events on the primary channel (when those channels recover)
/// rather than from rich detail in the fallback events themselves.
///
/// The fallback sink **must not panic**; if it does, the substrate
/// logs to stderr and aborts the process (§4.3).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum FallbackAuditEvent {
    /// A primary sink panicked during emission. Recorded by the
    /// [`crate::audit::SinkPanicGuard`] machinery (§4.3). §6.6.
    ///
    /// (Renamed from Phase 1's `SinkPanic` to match §6.6's
    /// committed identifier.)
    SinkPanicked {
        /// Which sink panicked.
        sink: SinkKind,
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Capability whose recording triggered the panic.
        capability: CapabilityKind,
        /// Emission wallclock (§6.1).
        at: SystemTime,
    },
    /// A `composite_audit` scope encountered unrecoverable
    /// inconsistency — rollback markers couldn't be emitted to
    /// every committed sink. Operators reading this must treat the
    /// affected `composite_op_id` as having partial coverage. §6.6.
    ///
    /// Correlation of [`Self::CompositeFailure`] events to primary-
    /// channel `CompositeRollbackMarker` events by
    /// `composite_op_id` is best-effort within the
    /// [`crate::audit::TRACKER_GRACE_WINDOW_DEFAULT`] /
    /// [`crate::audit::TRACKER_GRACE_WINDOW_MAX`] window (§4.9).
    /// Markers attempted after grace expiry are rejected by the
    /// tracker and do not appear on the primary channels; the
    /// fallback event records the composite failure unconditionally
    /// regardless.
    CompositeFailure {
        /// Forensic trace id (§6.1).
        trace_id: TraceId,
        /// Identifies the composite scope this failure ends.
        composite_op_id: CompositeOpId,
        /// Sinks that committed before the failure.
        sinks_committed: smallvec::SmallVec<[SinkKind; 4]>,
        /// Sinks that failed mid-flight.
        sinks_failed: smallvec::SmallVec<[SinkKind; 4]>,
        /// Emission wallclock (§6.1).
        at: SystemTime,
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
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::authority::capability::CapabilityKind;
    use crate::authority::predicate::{BindFailureReason, BindOutcomeRepr, DenialReason, SemVer};
    use crate::identity::{
        KeyId, PublicKey, ServiceIdentity, SessionDigest, SessionId, SignatureAlgorithm, TraceId,
    };
    use crate::ingress::{AttributionChain, Requester};
    use crate::oracle::{BlockOracleQuery, OracleKind, OracleQueryKind};
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

    fn sample_service_identity() -> ServiceIdentity {
        ServiceIdentity::new_internal(
            sample_did(),
            KeyId::from_bytes([0u8; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn sample_session_digest() -> SessionDigest {
        SessionDigest::from_bytes([0u8; 32])
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
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(123);
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

    // ============================================================
    // §6.3 channel-class
    // ============================================================

    /// §6.3 commits exactly seven variants in this order:
    /// `ChannelBound`, `ChannelIssuanceDenied`,
    /// `ChannelReborrowFailed`, `SyncBatchRejected`,
    /// `ChannelClosed`, `UnknownSessionMessage`,
    /// `CompositeRollbackMarker`.
    #[test]
    fn channel_audit_event_v1_variant_set_pinned() {
        let trace_id = sample_trace_id();
        let at = SystemTime::UNIX_EPOCH;
        let peer = sample_service_identity();
        let digest = sample_session_digest();
        let endpoint = CapabilityKind::ViewPrivate;

        let bound = ChannelAuditEvent::ChannelBound {
            trace_id,
            peer: peer.clone(),
            session_digest: digest,
            endpoint,
            outcome: BindOutcomeRepr::Success,
            at,
        };
        let denied = ChannelAuditEvent::ChannelIssuanceDenied {
            trace_id,
            peer: peer.clone(),
            endpoint,
            reason: DenialReason::OwnershipCheckFailed,
            at,
        };
        let reborrow = ChannelAuditEvent::ChannelReborrowFailed {
            trace_id,
            peer: peer.clone(),
            session_digest: digest,
            endpoint,
            reason: BindFailureReason::AuditUnavailable,
            at,
        };
        let batch = ChannelAuditEvent::SyncBatchRejected {
            trace_id,
            peer: peer.clone(),
            session_digest: digest,
            perspective: SyncPerspective::LocalAsReceiver,
            reason: BatchRejectionReason::UnauthorizedPeer,
            at,
        };
        let closed = ChannelAuditEvent::ChannelClosed {
            trace_id,
            peer,
            session_digest: digest,
            cause: ChannelCloseCause::CleanClose,
            at,
        };
        let unknown = ChannelAuditEvent::UnknownSessionMessage {
            trace_id,
            session_id_received: SessionId::from_bytes([0u8; 32]),
            peer_identity: None,
            at,
        };
        let rollback = ChannelAuditEvent::CompositeRollbackMarker {
            trace_id,
            composite_op_id: CompositeOpId::from_bytes([0u8; 16]),
            failing_sink: SinkKind::User,
            at,
        };

        for ev in [bound, denied, reborrow, batch, closed, unknown, rollback] {
            match ev {
                ChannelAuditEvent::ChannelBound { .. }
                | ChannelAuditEvent::ChannelIssuanceDenied { .. }
                | ChannelAuditEvent::ChannelReborrowFailed { .. }
                | ChannelAuditEvent::SyncBatchRejected { .. }
                | ChannelAuditEvent::ChannelClosed { .. }
                | ChannelAuditEvent::UnknownSessionMessage { .. }
                | ChannelAuditEvent::CompositeRollbackMarker { .. } => {}
            }
        }
    }

    /// §6.3 round-1 patch F4 introduces [`SyncPerspective`] with
    /// exactly two variants. The kickoff names them
    /// `Sender`/`Receiver` but §6.3 commits
    /// `LocalAsSender`/`LocalAsReceiver`; the spec wording is
    /// authoritative.
    #[test]
    fn sync_perspective_v1_variant_set_pinned() {
        for p in [SyncPerspective::LocalAsSender, SyncPerspective::LocalAsReceiver] {
            match p {
                SyncPerspective::LocalAsSender | SyncPerspective::LocalAsReceiver => {}
            }
        }
    }

    /// §6.3 commits exactly five `BatchRejectionReason` variants.
    #[test]
    fn batch_rejection_reason_v1_variant_set_pinned() {
        let v1 = BatchRejectionReason::LexiconSetMajorVersionMismatch {
            local: SemVer::new(1, 0, 0),
            peer: SemVer::new(2, 0, 0),
        };
        let v2 = BatchRejectionReason::UnauthorizedPeer;
        let v3 = BatchRejectionReason::HandshakeSignatureInvalid;
        let v4 = BatchRejectionReason::HandshakeTimeout;
        let v5 = BatchRejectionReason::HandshakeNonceReplay {
            first_seen_at: SystemTime::UNIX_EPOCH,
        };
        for r in [v1, v2, v3, v4, v5] {
            match r {
                BatchRejectionReason::LexiconSetMajorVersionMismatch { .. }
                | BatchRejectionReason::UnauthorizedPeer
                | BatchRejectionReason::HandshakeSignatureInvalid
                | BatchRejectionReason::HandshakeTimeout
                | BatchRejectionReason::HandshakeNonceReplay { .. } => {}
            }
        }
    }

    /// §6.3 commits exactly five `ChannelCloseCause` variants.
    #[test]
    fn channel_close_cause_v1_variant_set_pinned() {
        for c in [
            ChannelCloseCause::CleanClose,
            ChannelCloseCause::PeerDisconnected,
            ChannelCloseCause::Timeout,
            ChannelCloseCause::SubstrateShutdown,
            ChannelCloseCause::ProtocolError { detail: "test" },
        ] {
            match c {
                ChannelCloseCause::CleanClose
                | ChannelCloseCause::PeerDisconnected
                | ChannelCloseCause::Timeout
                | ChannelCloseCause::SubstrateShutdown
                | ChannelCloseCause::ProtocolError { .. } => {}
            }
        }
    }

    // ============================================================
    // §6.4 substrate-class
    // ============================================================

    /// §6.4 commits exactly twelve variants: seven core substrate
    /// plus five §7-shaped (rotation, invalidation, three
    /// peer-trust). Variant ordering follows §6.4's prose order.
    #[test]
    fn substrate_audit_event_v1_variant_set_pinned() {
        let trace_id = sample_trace_id();
        let at = SystemTime::UNIX_EPOCH;
        let svc = sample_service_identity();
        let cap = CapabilityKind::ViewPrivate;
        let target = sample_target_repr();

        let bound = SubstrateAuditEvent::ScopeBound {
            trace_id,
            service: svc.clone(),
            scope_repr: target.clone(),
            capability: cap,
            outcome: BindOutcomeRepr::Success,
            at,
        };
        let denied = SubstrateAuditEvent::ScopeIssuanceDenied {
            trace_id,
            service: svc.clone(),
            capability: cap,
            reason: DenialReason::OwnershipCheckFailed,
            at,
        };
        let lex = SubstrateAuditEvent::LexiconSetVersionChanged {
            trace_id,
            from_version: SemVer::new(1, 0, 0),
            to_version: SemVer::new(1, 1, 0),
            deprecations: vec![DeprecationEventDetail {
                nsid: crate::Nsid::new("tools.kryphocron.feed.like").unwrap(),
                since_version: SemVer::new(1, 1, 0),
                successor: None,
            }],
            additions: vec![],
            at,
        };
        let dep = SubstrateAuditEvent::DeprecatedWriteDuringGrace {
            trace_id,
            nsid: "tools.kryphocron.feed.like",
            capability: cap,
            requester: sample_did(),
            since_version: SemVer::new(1, 1, 0),
            grace_until: SystemTime::UNIX_EPOCH + Duration::from_secs(3600),
            successor: None,
            at,
        };
        let oracle = SubstrateAuditEvent::OracleFreshnessTransition {
            trace_id,
            oracle: OracleKind::Block,
            from_state: OracleFreshnessState::Fresh,
            to_state: OracleFreshnessState::Stale {
                exceeded_bound_by: Duration::from_secs(5),
            },
            sync_age: Duration::from_secs(60),
            at,
        };
        let rl = SubstrateAuditEvent::RateLimitTriggered {
            trace_id,
            requester: Requester::Anonymous,
            bucket: RateLimitBucket::AnonymousClass,
            at,
        };
        let rollback = SubstrateAuditEvent::CompositeRollbackMarker {
            trace_id,
            composite_op_id: CompositeOpId::from_bytes([0u8; 16]),
            failing_sink: SinkKind::User,
            at,
        };
        let did_rot = SubstrateAuditEvent::DidDocumentRotated {
            trace_id,
            did: sample_did(),
            previous_methods: vec![KeyId::from_bytes([0u8; 32])],
            current_methods: vec![KeyId::from_bytes([1u8; 32])],
            at,
        };
        let did_inv = SubstrateAuditEvent::DidDocumentInvalidated {
            trace_id,
            did: sample_did(),
            invalidated_by: InvalidationSource::Operator,
            at,
        };
        let trust_g = SubstrateAuditEvent::PeerTrustGranted {
            trace_id,
            peer: svc.clone(),
            operation: PeerOperation::AcceptSyncHandshake,
            kind: PeerKind::Federation,
            constraints: None,
            at,
        };
        let trust_d = SubstrateAuditEvent::PeerTrustDenied {
            trace_id,
            peer: svc.clone(),
            operation: PeerOperation::ReplicateRecord,
            reason: "test",
            at,
        };
        let trust_u = SubstrateAuditEvent::PeerTrustUnknown {
            trace_id,
            peer: svc,
            operation: PeerOperation::AcceptCapabilityClaim,
            fallback_applied: FallbackTrustPolicy::PromptOperator,
            interim_decision_applied: PeerTrustDecision::Deferred,
            at,
        };

        for ev in [
            bound, denied, lex, dep, oracle, rl, rollback, did_rot, did_inv, trust_g,
            trust_d, trust_u,
        ] {
            match ev {
                SubstrateAuditEvent::ScopeBound { .. }
                | SubstrateAuditEvent::ScopeIssuanceDenied { .. }
                | SubstrateAuditEvent::LexiconSetVersionChanged { .. }
                | SubstrateAuditEvent::DeprecatedWriteDuringGrace { .. }
                | SubstrateAuditEvent::OracleFreshnessTransition { .. }
                | SubstrateAuditEvent::RateLimitTriggered { .. }
                | SubstrateAuditEvent::CompositeRollbackMarker { .. }
                | SubstrateAuditEvent::DidDocumentRotated { .. }
                | SubstrateAuditEvent::DidDocumentInvalidated { .. }
                | SubstrateAuditEvent::PeerTrustGranted { .. }
                | SubstrateAuditEvent::PeerTrustDenied { .. }
                | SubstrateAuditEvent::PeerTrustUnknown { .. } => {}
            }
        }
    }

    /// §6.4 `OracleFreshnessState` is a two-variant enum.
    #[test]
    fn oracle_freshness_state_v1_variant_set_pinned() {
        for s in [
            OracleFreshnessState::Fresh,
            OracleFreshnessState::Stale {
                exceeded_bound_by: Duration::from_millis(1),
            },
        ] {
            match s {
                OracleFreshnessState::Fresh | OracleFreshnessState::Stale { .. } => {}
            }
        }
    }

    /// §6.4 `RateLimitBucket` enumerates four buckets.
    #[test]
    fn rate_limit_bucket_v1_variant_set_pinned() {
        for b in [
            RateLimitBucket::PerDidActive,
            RateLimitBucket::LongTailDidClass,
            RateLimitBucket::ServiceClass,
            RateLimitBucket::AnonymousClass,
        ] {
            match b {
                RateLimitBucket::PerDidActive
                | RateLimitBucket::LongTailDidClass
                | RateLimitBucket::ServiceClass
                | RateLimitBucket::AnonymousClass => {}
            }
        }
    }

    /// §6.4 `InvalidationSource` is a two-variant enum.
    #[test]
    fn invalidation_source_v1_variant_set_pinned() {
        for s in [
            InvalidationSource::Operator,
            InvalidationSource::Substrate { reason: "test" },
        ] {
            match s {
                InvalidationSource::Operator | InvalidationSource::Substrate { .. } => {}
            }
        }
    }

    /// §7-shaped placeholder `PeerOperation` ships with three v1
    /// variants matching `crate::resolver::TrustOperation`. Phase 4
    /// may extend.
    #[test]
    fn peer_operation_v1_variant_set_pinned() {
        for o in [
            PeerOperation::AcceptSyncHandshake,
            PeerOperation::AcceptCapabilityClaim,
            PeerOperation::ReplicateRecord,
        ] {
            match o {
                PeerOperation::AcceptSyncHandshake
                | PeerOperation::AcceptCapabilityClaim
                | PeerOperation::ReplicateRecord => {}
            }
        }
    }

    /// §7-shaped placeholder `FallbackTrustPolicy` ships with three
    /// v1 variants; `PromptOperator` is the one §6.4 explicitly
    /// names.
    #[test]
    fn fallback_trust_policy_v1_variant_set_pinned() {
        for p in [
            FallbackTrustPolicy::PromptOperator,
            FallbackTrustPolicy::DefaultDeny,
            FallbackTrustPolicy::DefaultAllow,
        ] {
            match p {
                FallbackTrustPolicy::PromptOperator
                | FallbackTrustPolicy::DefaultDeny
                | FallbackTrustPolicy::DefaultAllow => {}
            }
        }
    }

    /// §7-shaped placeholder `PeerTrustDecision` ships with three
    /// v1 variants.
    #[test]
    fn peer_trust_decision_v1_variant_set_pinned() {
        for d in [
            PeerTrustDecision::Accept,
            PeerTrustDecision::Reject,
            PeerTrustDecision::Deferred,
        ] {
            match d {
                PeerTrustDecision::Accept
                | PeerTrustDecision::Reject
                | PeerTrustDecision::Deferred => {}
            }
        }
    }

    // ============================================================
    // §6.5 moderation-class
    // ============================================================

    fn sample_rationale() -> ModeratorRationale {
        ModeratorRationale::Declared(
            BoundedString::<MAX_RATIONALE_LEN>::new("test rationale").unwrap(),
        )
    }

    fn sample_case() -> ModerationCaseId {
        ModerationCaseId::from_bytes([0u8; 16])
    }

    /// §6.5 commits exactly five `ModerationAuditEvent` variants
    /// in this order: `ModeratorInspected`, `ModeratorTookDown`,
    /// `ModeratorRestored`, `ModerationIssuanceDenied`,
    /// `CompositeRollbackMarker`.
    ///
    /// Note: kickoff prose names them `ModeratorRead`,
    /// `ModeratorTakedown`, `ModeratorRestored`; spec §6.5
    /// commits `ModeratorInspected`, `ModeratorTookDown`,
    /// `ModeratorRestored`. Spec wording is authoritative.
    #[test]
    fn moderation_audit_event_v1_variant_set_pinned() {
        let trace_id = sample_trace_id();
        let at = SystemTime::UNIX_EPOCH;
        let moderator = sample_did();
        let case = sample_case();
        let target = sample_target_repr();
        let rationale = sample_rationale();

        let inspected = ModerationAuditEvent::ModeratorInspected {
            trace_id,
            moderator: moderator.clone(),
            case,
            target_repr: target.clone(),
            rationale: rationale.clone(),
            at,
        };
        let took_down = ModerationAuditEvent::ModeratorTookDown {
            trace_id,
            moderator: moderator.clone(),
            case,
            target_repr: target.clone(),
            outcome: BindOutcomeRepr::Success,
            rationale: rationale.clone(),
            at,
        };
        let restored = ModerationAuditEvent::ModeratorRestored {
            trace_id,
            moderator: moderator.clone(),
            case,
            target_repr: target,
            outcome: BindOutcomeRepr::Success,
            rationale,
            at,
        };
        let denied = ModerationAuditEvent::ModerationIssuanceDenied {
            trace_id,
            moderator,
            capability: CapabilityKind::ViewPrivate,
            reason: DenialReason::OwnershipCheckFailed,
            at,
        };
        let rollback = ModerationAuditEvent::CompositeRollbackMarker {
            trace_id,
            composite_op_id: CompositeOpId::from_bytes([0u8; 16]),
            failing_sink: SinkKind::Substrate,
            at,
        };

        for ev in [inspected, took_down, restored, denied, rollback] {
            match ev {
                ModerationAuditEvent::ModeratorInspected { .. }
                | ModerationAuditEvent::ModeratorTookDown { .. }
                | ModerationAuditEvent::ModeratorRestored { .. }
                | ModerationAuditEvent::ModerationIssuanceDenied { .. }
                | ModerationAuditEvent::CompositeRollbackMarker { .. } => {}
            }
        }
    }

    /// §6.5 round-1 patch F2: `MAX_RATIONALE_LEN = 4096`.
    #[test]
    fn max_rationale_len_pinned_at_4096() {
        assert_eq!(MAX_RATIONALE_LEN, 4096);
    }

    /// §6.5 round-1 patch F2 boundary: rationales of length
    /// `MAX_RATIONALE_LEN` accepted; longer rejected at
    /// construction. Validation happens at `BoundedString::new`,
    /// not at audit-emit time, keeping the audit-emit path
    /// infallible-on-length.
    #[test]
    fn moderator_rationale_boundary_at_max_rationale_len() {
        let exact = "a".repeat(MAX_RATIONALE_LEN);
        let over = "a".repeat(MAX_RATIONALE_LEN + 1);

        let ok = BoundedString::<MAX_RATIONALE_LEN>::new(exact).unwrap();
        let _r = ModeratorRationale::Declared(ok);

        let err = BoundedString::<MAX_RATIONALE_LEN>::new(over).unwrap_err();
        assert_eq!(err.bound, MAX_RATIONALE_LEN);
        assert_eq!(err.len, MAX_RATIONALE_LEN + 1);
    }

    /// §6.5 commits `ModeratorRationale` as a `#[non_exhaustive]`
    /// enum with `Declared(BoundedString<MAX_RATIONALE_LEN>)` as
    /// the v1 variant. Future versions may add structured
    /// rationale-reference variants additively.
    #[test]
    fn moderator_rationale_v1_variant_set_pinned() {
        let r = sample_rationale();
        match r {
            ModeratorRationale::Declared(_) => {}
        }
    }

    // ============================================================
    // §6.6 fallback channel
    // ============================================================

    /// §6.6 commits exactly two `FallbackAuditEvent` variants:
    /// `SinkPanicked` (renamed from Phase 1's `SinkPanic`) and
    /// `CompositeFailure`. Both gained an explicit `at:
    /// SystemTime` field per §6.1.
    #[test]
    fn fallback_audit_event_v1_variant_set_pinned() {
        let trace_id = sample_trace_id();
        let at = SystemTime::UNIX_EPOCH;

        let panicked = FallbackAuditEvent::SinkPanicked {
            sink: SinkKind::User,
            trace_id,
            capability: CapabilityKind::ViewPrivate,
            at,
        };
        let composite = FallbackAuditEvent::CompositeFailure {
            trace_id,
            composite_op_id: CompositeOpId::from_bytes([0u8; 16]),
            sinks_committed: smallvec::smallvec![SinkKind::User, SinkKind::Substrate],
            sinks_failed: smallvec::smallvec![SinkKind::Channel],
            at,
        };

        for ev in [panicked, composite] {
            match ev {
                FallbackAuditEvent::SinkPanicked { .. }
                | FallbackAuditEvent::CompositeFailure { .. } => {}
            }
        }
    }

    /// §6.6 migrated `sinks_committed` and `sinks_failed` from
    /// `Vec<SinkKind>` to `SmallVec<[SinkKind; 4]>` to avoid heap
    /// allocations in the common ≤4-sinks-per-composite case.
    #[test]
    fn fallback_composite_failure_uses_smallvec_inline_for_le_4_sinks() {
        let four: smallvec::SmallVec<[SinkKind; 4]> = smallvec::smallvec![
            SinkKind::User,
            SinkKind::Channel,
            SinkKind::Substrate,
            SinkKind::Moderation,
        ];
        // Inline-cap = 4: a four-element SmallVec lives on the
        // stack rather than the heap.
        assert!(!four.spilled());
    }
}

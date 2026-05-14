//! §4.3 capability issuance, proof types, and the v1 capability
//! vocabulary.
//!
//! Four issuance chokepoints — one per capability class — and
//! four parallel proof families. The chokepoints are the **only**
//! way to produce proof values; consumer code cannot construct
//! a proof value via struct-literal syntax because the proof
//! types carry private `PhantomData<sealed::Token>` fields.

pub(crate) mod capability;
pub(crate) mod moderation;
pub(crate) mod predicate;
pub(crate) mod proof;
pub(crate) mod subjects;
pub(crate) mod v1;

use std::time::Instant;

use crate::identity::TraceId;
use crate::ingress::AuthContext;
use crate::proto::Did;

pub use self::capability::{
    CapabilityClass, CapabilityKind, CapabilitySemantics, CapabilitySet, Endpoint,
    ModerationCapability, OracleConsultations, OracleResultsForCapability, SubstrateScope,
    UserCapability,
};
pub use self::moderation::{
    InspectionKind, InspectionNotification, InspectionNotificationQueueReader,
    NotificationId,
};
pub use self::predicate::{
    AuthDenial, BindError, BindFailureReason, BindOutcomeRepr, DenialReason, IssuancePolicy,
    PipelineStage, PredicateContext, SemVer,
};
pub use self::proof::{
    AuthorityId, BoundChannelProof, BoundModerationProof, BoundSubstrateProof,
    BoundUserProof, ChannelProof, ChannelProofRef, ModerationProof, ModerationProofRef,
    SubstrateProof, SubstrateProofRef, UserProof, UserProofRef,
};
pub use self::subjects::{
    AudienceListId, ChannelBinding, ManageAudienceSubject, ModerationCaseId,
    ModerationSubject, RecordStateFilter, ResourceId, ScopeError, ScopeSelector, ShardId,
    ShardRange, TimeWindow,
};
pub use self::v1::{
    AppViewSync, DeletePrivatePost, DeletePrivatePostOracleResults, EditPrivatePost,
    EditPrivatePostOracleResults, EmitToSyncChannel, GarbageCollect, GraphSync,
    ManageAudience, ManageAudienceOracleResults, ModeratorRead, ModeratorRestore,
    ModeratorTakedown, ParticipatePrivate, ParticipatePrivateOracleResults,
    ReplicatePrivate, ScanShard, ViewPrivate, ViewPrivateOracleResults,
};

// ============================================================
// Issuance chokepoints (§4.3).
// ============================================================
//
// Four functions, one per class. Phase 1 ships stubs that
// produce a structured `AuthDenial` rather than a working proof;
// Phase 4 wires the §4.3 pipeline through the chokepoint.

/// Issue a user-class capability proof (§4.3).
///
/// **Phase 1 stub.** Returns
/// [`AuthDenial::AuditUnavailable`]. Phase 4 wires:
///
/// 1. Stage-0 deprecation gate (§5.6).
/// 2. Two-tier per-issuer rate limiting (§4.9).
/// 3. Oracle freshness check.
/// 4. Capability-issuance pipeline.
/// 5. Proof construction with current `Instant`.
///
/// # Errors
///
/// Returns [`AuthDenial`] on any pipeline denial, rate-limiting,
/// oracle staleness, or audit-sink failure.
pub fn issue_user<C>(
    _ctx: &AuthContext<'_>,
    _target: <C as UserCapability>::Subject,
) -> Result<UserProof<C>, AuthDenial>
where
    C: UserCapability + IssuancePolicy,
{
    unimplemented!("§4.3 authority::issue_user: Phase 4 wires the pipeline");
}

/// Issue a channel-class capability proof (§4.3).
///
/// **Phase 1 stub.**
///
/// # Errors
///
/// Returns [`AuthDenial`] on any pipeline denial.
pub fn issue_channel<E>(
    _ctx: &AuthContext<'_>,
    _target: <E as Endpoint>::Subject,
) -> Result<ChannelProof<E>, AuthDenial>
where
    E: Endpoint,
{
    unimplemented!("§4.3 authority::issue_channel: Phase 4 wires the pipeline");
}

/// Issue a substrate-class capability proof (§4.3).
///
/// `SubstrateProof` issuance accepts only non-interactive
/// service principals (§4.6 read-everything-authority
/// discipline). Phase 4 enforces this; Phase 1 stubs.
///
/// **Phase 1 stub.**
///
/// # Errors
///
/// Returns [`AuthDenial`] on denial.
pub fn issue_substrate<S>(
    _ctx: &AuthContext<'_>,
    _target: <S as SubstrateScope>::Subject,
) -> Result<SubstrateProof<S>, AuthDenial>
where
    S: SubstrateScope,
{
    unimplemented!("§4.3 authority::issue_substrate: Phase 4 wires the pipeline");
}

/// Issue a moderation-class capability proof (§4.3).
///
/// `ModeratorRead` bind emits two audit events per §4.9 (one to
/// the moderation sink, one to the owner's inspection-notification
/// queue). Phase 4 wires the dual-emit.
///
/// **Phase 1 stub.**
///
/// # Errors
///
/// Returns [`AuthDenial`] on denial.
pub fn issue_moderation<C>(
    _ctx: &AuthContext<'_>,
    _target: <C as ModerationCapability>::Subject,
) -> Result<ModerationProof<C>, AuthDenial>
where
    C: ModerationCapability,
{
    unimplemented!("§4.3 authority::issue_moderation: Phase 4 wires the pipeline");
}

// ============================================================
// Crate-internal construction helpers (used by Phase 4).
// ============================================================

/// Crate-internal constructor for [`UserProof`]. Reserved for
/// Phase 4's pipeline implementation.
#[doc(hidden)]
pub(crate) fn construct_user_proof<C: UserCapability>(
    requester: Did,
    subject: <C as UserCapability>::Subject,
    issued_at: Instant,
    issuer: AuthorityId,
    trace_id: TraceId,
) -> UserProof<C> {
    UserProof::new_internal(requester, subject, issued_at, issuer, trace_id)
}

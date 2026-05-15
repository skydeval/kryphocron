// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

use std::sync::OnceLock;
use std::time::Instant;

use crate::ingress::{AuthContext, Requester};
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
/// Pipeline (Phase 7c v0.1):
///
/// - **Stage 1 — requester authority.** User-class accepts
///   [`Requester::Did`] (the user themselves) and
///   [`Requester::Service`] (a substrate dispatching on the
///   user's behalf). [`Requester::Anonymous`] fails closed with
///   [`AuthDenial::RequesterLacksAuthority`].
/// - **Stage 3 — proof construction.** Builds a
///   [`UserProof<C>`] with `issued_at = Instant::now()` and a
///   process-static [`AuthorityId`] (see
///   [`process_authority_id`]).
///
/// Stage 0 (§5.6 lexicon-deprecation gate) and stage 2 (subject
/// ownership / authority check) defer to bind (Phase 7d). Stage 0
/// requires generic NSID extraction from the typed `Subject`; stage 2
/// is the bind-time predicate's domain
/// ([`DenialReason::OwnershipCheckFailed`](crate::DenialReason)).
///
/// # Errors
///
/// Returns [`AuthDenial::RequesterLacksAuthority`] if the
/// requester is anonymous. Future variants (oracle-staleness,
/// rate-limiting, JWT-scope mismatch routed through
/// [`check_jwt_scope_for`]) land in subsequent phases.
pub fn issue_user<C>(
    ctx: &AuthContext<'_>,
    subject: <C as UserCapability>::Subject,
) -> Result<UserProof<C>, AuthDenial>
where
    C: UserCapability + IssuancePolicy,
{
    let requester = stage1_extract_requester_did(ctx, CapabilityClass::User, true)?;
    Ok(UserProof::new_internal(
        requester,
        subject,
        Instant::now(),
        process_authority_id(),
        ctx.trace_id(),
    ))
}

/// Issue a channel-class capability proof (§4.3).
///
/// Pipeline (Phase 7c v0.1):
///
/// - **Stage 1 — requester authority.** Channel-class accepts
///   [`Requester::Did`] (a user dispatching a channel
///   subscription) and [`Requester::Service`] (an operator
///   dispatching channel events on the user's behalf).
///   [`Requester::Anonymous`] fails closed.
/// - **Stage 3 — proof construction.** Builds a
///   [`ChannelProof<E>`] with `issued_at = Instant::now()` and a
///   process-static [`AuthorityId`].
///
/// Stage 0 (lexicon deprecation) does not apply to channel-class
/// — channel subjects ([`crate::ChannelBinding`]) carry no NSID.
/// Stage 2 (endpoint validation) is the bind-time predicate's
/// domain.
///
/// # Errors
///
/// Returns [`AuthDenial::RequesterLacksAuthority`] if the
/// requester is anonymous.
pub fn issue_channel<E>(
    ctx: &AuthContext<'_>,
    subject: <E as Endpoint>::Subject,
) -> Result<ChannelProof<E>, AuthDenial>
where
    E: Endpoint,
{
    let requester = stage1_extract_requester_did(ctx, CapabilityClass::Channel, true)?;
    Ok(ChannelProof::new_internal(
        requester,
        subject,
        Instant::now(),
        process_authority_id(),
        ctx.trace_id(),
    ))
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
// §7.2 JWT-scope enforcement (Phase 4a).
// ============================================================

/// Match the verified JWT's scope against capability `C`'s
/// declared scope requirement (§7.2).
///
/// `Ok(())` if `C::required_jwt_scope()` is `None` (no scope
/// requirement applies) or if the JWT's scope set contains the
/// required value. `Err(AuthDenial::ScopeMismatch)` otherwise.
///
/// **Empty scope is fail-closed** per §7.2: a JWT with no scope
/// claim presented for a capability that requires a scope value
/// fails with `granted: SmallVec::new()`. Issuance paths surface
/// this as
/// [`crate::audit::UserAuditEvent::CapabilityIssuanceDenied`] with
/// [`crate::authority::DenialReason::JwtScopeInsufficient`] —
/// Phase 4a wires
/// the matching mechanism; the bind-pipeline surface that
/// translates the denial to the audit event is staged for the
/// later Phase 4 sub-phases that bring `issue_user::<C>` out of
/// stub state.
///
/// # Errors
///
/// Returns [`AuthDenial::ScopeMismatch`] when `C` requires a
/// scope and the JWT's `JwtScope::scopes` does not contain it.
pub fn check_jwt_scope_for<C: IssuancePolicy>(
    jwt_scope: &crate::verification::JwtScope,
) -> Result<(), AuthDenial> {
    check_jwt_scope_required(<C as IssuancePolicy>::required_jwt_scope(), jwt_scope)
}

/// The scope-matching primitive [`check_jwt_scope_for`] wraps.
/// Crate-internal so tests can pin scope-required behavior
/// without standing up a full `IssuancePolicy` impl (which would
/// require a sealed `OracleResultsForCapability` type that only
/// the `capability_marker!` macro can produce).
pub(crate) fn check_jwt_scope_required(
    required: Option<&'static str>,
    jwt_scope: &crate::verification::JwtScope,
) -> Result<(), AuthDenial> {
    let Some(required) = required else {
        return Ok(());
    };
    if jwt_scope.scopes.iter().any(|s| s == required) {
        return Ok(());
    }
    Err(AuthDenial::ScopeMismatch {
        required: required.to_string(),
        granted: jwt_scope.scopes.clone(),
    })
}

// ============================================================
// Phase 7c §4.3 issuance internals.
// ============================================================

/// §4.3 stage 1: extract the requester [`Did`] from `ctx`,
/// failing with [`AuthDenial::RequesterLacksAuthority`] if the
/// requester does not carry the authority required to issue
/// `class`.
///
/// `accept_did` controls whether [`Requester::Did`] is admitted:
/// user-class and channel-class pass `true` (interactive issuance
/// allowed); substrate-class and moderation-class pass `false`
/// (Service-only issuance, per §4.6 read-everything-authority and
/// §4.3 moderation-as-service discipline). [`Requester::Anonymous`]
/// is rejected by every chokepoint regardless of `accept_did`.
fn stage1_extract_requester_did(
    ctx: &AuthContext<'_>,
    class: CapabilityClass,
    accept_did: bool,
) -> Result<Did, AuthDenial> {
    match ctx.requester() {
        Requester::Did(did) if accept_did => Ok(did.clone()),
        Requester::Service(service) => Ok(service.service_did().clone()),
        other => Err(AuthDenial::RequesterLacksAuthority {
            class,
            found: other.kind(),
        }),
    }
}

/// Process-static [`AuthorityId`] (§4.3).
///
/// Lazy-initialized from the OS CSPRNG on first use via
/// [`OnceLock`] + [`getrandom::getrandom`]. The `AuthorityId`
/// names the substrate's authority-module instance for the
/// lifetime of the process; multiple substrates running in
/// distinct processes will pick distinct ids with overwhelming
/// probability (16 bytes from CSPRNG).
///
/// CSPRNG failure is treated as fatal: if `getrandom` itself
/// fails (a rare condition signalling OS-level entropy
/// unavailability), the substrate cannot establish a stable
/// authority identity and the panic surfaces the failure rather
/// than falsifying it with all-zeros.
fn process_authority_id() -> AuthorityId {
    static AUTHORITY_ID: OnceLock<AuthorityId> = OnceLock::new();
    *AUTHORITY_ID.get_or_init(|| {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)
            .expect("§4.3 authority-id init: OS CSPRNG unavailable");
        AuthorityId::from_bytes(bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::v1::ViewPrivate;
    use crate::verification::JwtScope;
    use smallvec::{smallvec, SmallVec};

    /// §7.2: when no scope is required, any JWT scope (including
    /// empty) succeeds. Phase 1's v1 capabilities all inherit the
    /// `None` default — pin via `ViewPrivate`.
    #[test]
    fn no_scope_required_succeeds_with_empty_jwt_scope() {
        let empty = JwtScope { scopes: SmallVec::new() };
        check_jwt_scope_for::<ViewPrivate>(&empty).unwrap();
        check_jwt_scope_required(None, &empty).unwrap();
    }

    #[test]
    fn no_scope_required_succeeds_with_arbitrary_jwt_scope() {
        let some = JwtScope {
            scopes: smallvec!["whatever".to_string()],
        };
        check_jwt_scope_for::<ViewPrivate>(&some).unwrap();
        check_jwt_scope_required(None, &some).unwrap();
    }

    /// §7.2: when a capability declares a required scope and the
    /// JWT's scope set contains it, issuance proceeds.
    #[test]
    fn scope_match_succeeds() {
        let granted = JwtScope {
            scopes: smallvec![
                "tools.kryphocron.test.scope".to_string(),
                "tools.kryphocron.other".to_string(),
            ],
        };
        check_jwt_scope_required(Some("tools.kryphocron.test.scope"), &granted).unwrap();
    }

    /// §7.2: when a capability declares a required scope and the
    /// JWT's scope set does NOT contain it, issuance fails with
    /// `AuthDenial::ScopeMismatch`.
    #[test]
    fn scope_mismatch_returns_scope_mismatch() {
        let granted = JwtScope {
            scopes: smallvec!["other.scope".to_string()],
        };
        let err = check_jwt_scope_required(Some("tools.kryphocron.test.scope"), &granted)
            .unwrap_err();
        match err {
            AuthDenial::ScopeMismatch { required, granted: g } => {
                assert_eq!(required, "tools.kryphocron.test.scope");
                assert_eq!(g.as_slice(), &["other.scope"]);
            }
            other => panic!("expected ScopeMismatch, got {other:?}"),
        }
    }

    /// §7.2 empty-is-fail-closed: a capability with a required
    /// scope presented with an empty JWT scope set fails with
    /// `granted: SmallVec::new()`.
    #[test]
    fn empty_scope_against_required_capability_fails_closed() {
        let empty = JwtScope { scopes: SmallVec::new() };
        let err = check_jwt_scope_required(Some("tools.kryphocron.test.scope"), &empty)
            .unwrap_err();
        match err {
            AuthDenial::ScopeMismatch { required, granted } => {
                assert_eq!(required, "tools.kryphocron.test.scope");
                assert!(granted.is_empty());
            }
            other => panic!("expected ScopeMismatch, got {other:?}"),
        }
    }

    /// §7.2 wires `DenialReason::JwtScopeInsufficient` and
    /// `BindOutcomeRepr::DeniedAtPipeline { stage:
    /// PipelineStage::JwtScope, ... }` as the audit-side renderings
    /// of a scope-mismatch denial. The mapping from
    /// `AuthDenial::ScopeMismatch` to those audit shapes lives in
    /// the bind-pipeline path (later Phase 4 sub-phase); this test
    /// pins that the variants exist and are constructible from
    /// outside the audit module.
    #[test]
    fn jwt_scope_insufficient_and_pipeline_stage_jwt_scope_reachable() {
        let _r = DenialReason::JwtScopeInsufficient {
            required: "scope".to_string(),
            granted: SmallVec::new(),
        };
        let _b = BindOutcomeRepr::DeniedAtPipeline {
            stage: PipelineStage::JwtScope,
            reason: DenialReason::JwtScopeInsufficient {
                required: "scope".to_string(),
                granted: SmallVec::new(),
            },
        };
    }
}

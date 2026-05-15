// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.3 capability proof types — four parallel families.
//!
//! Phase 4e (resolves CHAINLINKS #11): `dead_code` allowed at
//! module level because the proof types are public surface for
//! downstream substrates that bind / hold / consume proofs;
//! the kryphocron crate itself constructs them but does not
//! consume their fields directly. Phase 4f / Phase 5 wire
//! the consuming code paths.
#![allow(dead_code)]

//!
//! Each capability class has a triple:
//!
//! - `*Proof<C>` — the unbound proof issued by [`crate::authority`].
//! - `Bound*Proof<'p, C>` — the bound proof, the only type
//!   that grants access to the subject.
//! - `*ProofRef<'p, C>` — a non-`Copy` borrowed handle that
//!   reborrows from a bound proof.
//!
//! All twelve types share:
//!
//! - Private `_unconstructible_outside_crate: PhantomData<sealed::Token>`
//!   field that prevents struct-literal construction outside the
//!   crate (§4.3, §4.7 unforgeability discipline).
//! - No `Clone`, `Serialize`, `Default`, or `Arbitrary` derives
//!   (§4.3 forbidden-derives discipline).
//! - `bind` consumes `self` so move semantics foreclose
//!   double-emission of the terminal audit event.
//!
//! ## Phase 1 status
//!
//! `bind` and `reborrow` carry the right type signature and emit
//! a `todo!()` body. Phase 4 wires the §4.3 pipeline + audit-sink
//! dispatch; Phase 1 ships only the type architecture.

use core::marker::PhantomData;
use std::time::{Duration, Instant};

use crate::authority::capability::{
    CapabilityKind, Endpoint, ModerationCapability, SubstrateScope, UserCapability,
};
use crate::authority::predicate::{BindError, BindFailureReason, DenialReason, PipelineStage};
use crate::authority::subjects::HasResourceLocation;
use crate::identity::TraceId;
use crate::ingress::{AuthContext, Requester};
use crate::proto::Did;
use crate::sealed;

// ============================================================
// Phase 7d §4.3 bind/reborrow shared helpers + BindFlow.
// ============================================================

/// §4.3 bind-pipeline outcome carried via [`crate::composite_audit`]'s
/// `R` channel.
///
/// Bind paths run their pipeline inside `composite_audit` and need
/// the audit emission to be **committed** even on the denial path
/// — composite_audit drops queued events when the op closure
/// returns `Err`, so denial-with-audit cannot use the `Err`
/// channel. Instead the closure always returns `Ok(BindFlow)` and
/// the bind body unpacks the variant outside the audit call.
#[derive(Debug)]
enum BindFlow {
    /// Pipeline reached stage 6 (post-emit); proof construction
    /// proceeds.
    Success,
    /// A pipeline stage produced a structured denial. The audit
    /// emit for the denial event already happened inside the
    /// closure; the bind body surfaces the matching
    /// [`BindError::DeniedAtPipeline`] to the caller.
    DeniedAtPipeline {
        stage: PipelineStage,
        reason: DenialReason,
    },
}

/// §4.3 precheck: the proof's `subject` must equal the bind-call
/// `target`. Fail-fast precondition; runs before composite_audit
/// and emits no audit (a target mismatch is a caller error, not a
/// pipeline denial).
fn precheck_target_match<S: PartialEq>(
    proof_subject: &S,
    target: &S,
) -> Result<(), BindError> {
    if proof_subject == target {
        Ok(())
    } else {
        Err(BindError::TargetMismatch)
    }
}

/// §4.3 precheck: the proof's recorded requester must match the
/// AuthContext's resolved requester. Anonymous AuthContext can
/// never match a Did-bearing proof; both Did and Service requesters
/// project to a [`Did`] for comparison
/// ([`crate::identity::ServiceIdentity::service_did`]).
fn precheck_context_match(
    proof_requester: &Did,
    ctx: &AuthContext<'_>,
) -> Result<(), BindError> {
    let ctx_did = match ctx.requester() {
        Requester::Did(did) => did,
        Requester::Service(svc) => svc.service_did(),
        Requester::Anonymous => return Err(BindError::ContextMismatch),
    };
    if proof_requester == ctx_did {
        Ok(())
    } else {
        Err(BindError::ContextMismatch)
    }
}

/// §4.3 / §4.7 precheck: the proof must not have aged past
/// `max_age` since `issued_at`. Operators can shorten `max_age`
/// below the capability's compile-time `MAX_AGE`; we take the
/// caller's value verbatim.
fn precheck_expired(issued_at: Instant, max_age: Duration) -> Result<(), BindError> {
    if issued_at.elapsed() > max_age {
        Err(BindError::Expired)
    } else {
        Ok(())
    }
}

/// Convenience: current time as Unix-seconds. Powers
/// [`super::check_stage_0_deprecation`]'s grace-window comparison.
fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ============================================================
// AuthorityId — opaque issuer-identifier carried on every proof.
// ============================================================

/// Opaque identifier of the authority module instance that
/// issued a proof. Used for audit correlation; not a capability
/// artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorityId([u8; 16]);

impl AuthorityId {
    /// Construct an [`AuthorityId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        AuthorityId(bytes)
    }
}

// ============================================================
// User-class proof family.
// ============================================================

/// User-class capability proof. Issued by
/// [`crate::authority::issue_user`], consumed by [`UserProof::bind`].
///
/// **Unconstructible outside the crate in safe code** — the
/// `_unconstructible_outside_crate: PhantomData<sealed::Token>`
/// field has no public default and no public constructor.
#[must_use = "an unbound UserProof grants no access; call .bind to use it"]
pub struct UserProof<C: UserCapability> {
    requester: Did,
    subject: <C as UserCapability>::Subject,
    issued_at: Instant,
    issuer: AuthorityId,
    capability_kind: CapabilityKind,
    trace_id: TraceId,
    _capability: PhantomData<C>,
    _unconstructible_outside_crate: PhantomData<sealed::Token>,
}

impl<C: UserCapability> UserProof<C> {
    /// Crate-internal constructor. Use the [`crate::authority::issue_user`]
    /// entrypoint from consumer code.
    pub(crate) fn new_internal(
        requester: Did,
        subject: <C as UserCapability>::Subject,
        issued_at: Instant,
        issuer: AuthorityId,
        trace_id: TraceId,
    ) -> Self {
        UserProof {
            requester,
            subject,
            issued_at,
            issuer,
            capability_kind: C::KIND,
            trace_id,
            _capability: PhantomData,
            _unconstructible_outside_crate: PhantomData,
        }
    }

    /// Bind the proof against a target.
    ///
    /// Consumes `self`. Emits exactly one terminal audit event
    /// per §4.3 / §4.9 A1 invariant via [`crate::composite_audit`].
    /// On success returns [`BoundUserProof`]; on any non-success
    /// outcome the audit emit fires first and `Err(BindError)` is
    /// returned.
    ///
    /// Pipeline (Phase 7d v0.1):
    /// - **Pre-checks** (no audit): target match, context match,
    ///   expiry. Caller errors fail fast.
    /// - **Stage 0 — DeprecationGate** (write-semantics only): the
    ///   subject's NSID is consulted against
    ///   [`crate::KRYPHOCRON_LEXICON_REGISTRY`] (§5.6).
    /// - **Stage 2 — BlockConsultation**: consults
    ///   [`crate::oracle::BlockOracle`] for
    ///   [`crate::oracle::BlockOracleQuery::RequesterVsResourceOwner`]
    ///   (the universal query across v1 user-class capabilities).
    ///   Multi-query consultations (RequesterVsParentPostOwner,
    ///   audience queries, mute queries) defer to a v0.2 per-
    ///   capability oracle-results-builder trait — currently
    ///   stubbed via `<C::OracleResults as Default>::default()`.
    /// - **Stage 5 — Predicate**: invokes
    ///   [`crate::IssuancePolicy::capability_predicate`] with
    ///   default-initialized oracle results (see stage 2 note).
    /// - **Stage 6 — Timing equalization**: post-emit, sleeps
    ///   until `equalize_timing_target_for::<C>` elapses.
    ///
    /// # Errors
    ///
    /// Returns [`BindError::TargetMismatch`] /
    /// [`BindError::ContextMismatch`] / [`BindError::Expired`]
    /// for precondition failures (no audit emit). Returns
    /// [`BindError::DeniedAtPipeline`] for stage failures (audit
    /// emit fires first). Returns
    /// [`BindError::AuditUnavailable`] /
    /// [`BindError::AuditPanicked`] when the audit machinery
    /// itself fails.
    pub async fn bind<'p>(
        self,
        ctx: &AuthContext<'_>,
        target: &<C as UserCapability>::Subject,
    ) -> Result<BoundUserProof<'p, C>, BindError>
    where
        Self: 'p,
        <C as UserCapability>::Subject:
            PartialEq + crate::authority::HasResourceLocation,
        <C as UserCapability>::OracleResults: Default,
        C: crate::authority::IssuancePolicy,
    {
        let start = Instant::now();

        // Pre-checks (no audit emit; caller errors)
        precheck_target_match(&self.subject, target)?;
        precheck_context_match(&self.requester, ctx)?;
        precheck_expired(self.issued_at, C::MAX_AGE)?;

        // Build event-construction inputs from self before
        // entering the closure (composite_audit's op closure
        // captures by reference so we don't move self).
        let trace_id = self.trace_id;
        let proof_requester_did = self.requester.clone();
        let attribution = ctx.attribution_chain().clone();
        let now = std::time::SystemTime::now();
        let target_did = target.resource_did().clone();
        let target_nsid = target.resource_nsid().clone();
        let subject_repr = crate::target::TargetRepresentation::structural_only(
            crate::target::StructuralRepresentation::Resource {
                did: target_did.clone(),
                nsid: target_nsid.clone(),
            },
        );

        // Capture the AuthContext bits the closure needs (it can't
        // hold a borrow of `ctx` across the await point cleanly
        // for non-Sync trait objects, but the oracles are Send +
        // Sync trait objects, so a copy of the OracleSet is
        // allowed via its Copy derive).
        let oracles_block = ctx.oracles().block;
        let trace_id_for_predicate = trace_id;
        let attribution_ref_for_predicate = ctx.attribution_chain();
        let requester_ref_for_predicate = ctx.requester();

        let pipeline_result: Result<BindFlow, BindError> =
            crate::audit::composite_audit(trace_id, ctx.audit(), async |scope| {
                // Stage 0: deprecation gate (Write only)
                if matches!(
                    C::SEMANTICS,
                    crate::authority::CapabilitySemantics::Write
                ) {
                    if let Err(reason) = crate::authority::check_stage_0_deprecation(
                        &target_nsid,
                        now_unix_seconds(),
                    ) {
                        let event = crate::audit::UserAuditEvent::CapabilityIssuanceDenied {
                            trace_id,
                            requester: Requester::Did(proof_requester_did.clone()),
                            capability: C::KIND,
                            target_repr: subject_repr.clone(),
                            reason: reason.clone(),
                            attribution: attribution.clone(),
                            at: now,
                        };
                        scope.emit_user(event);
                        return Ok(BindFlow::DeniedAtPipeline {
                            stage: PipelineStage::DeprecationGate,
                            reason,
                        });
                    }
                }

                // Stage 2: BlockConsultation (universal query)
                let block_state =
                    oracles_block.block_state(&proof_requester_did, &target_did);
                if !matches!(block_state, crate::oracle::BlockState::None) {
                    let reason = DenialReason::Blocked {
                        query: crate::oracle::BlockOracleQuery::RequesterVsResourceOwner,
                        state: block_state,
                    };
                    let event = crate::audit::UserAuditEvent::CapabilityIssuanceDenied {
                        trace_id,
                        requester: Requester::Did(proof_requester_did.clone()),
                        capability: C::KIND,
                        target_repr: subject_repr.clone(),
                        reason: reason.clone(),
                        attribution: attribution.clone(),
                        at: now,
                    };
                    scope.emit_user(event);
                    return Ok(BindFlow::DeniedAtPipeline {
                        stage: PipelineStage::BlockConsultation,
                        reason,
                    });
                }

                // Stage 5: Predicate
                let oracle_results =
                    <<C as UserCapability>::OracleResults as Default>::default();
                let predicate_ctx = crate::authority::PredicateContext::new(
                    requester_ref_for_predicate,
                    trace_id_for_predicate,
                    attribution_ref_for_predicate,
                );
                if let Err(reason) =
                    <C as crate::authority::IssuancePolicy>::capability_predicate(
                        &predicate_ctx,
                        target,
                        &oracle_results,
                    )
                {
                    let event = crate::audit::UserAuditEvent::CapabilityIssuanceDenied {
                        trace_id,
                        requester: Requester::Did(proof_requester_did.clone()),
                        capability: C::KIND,
                        target_repr: subject_repr.clone(),
                        reason: reason.clone(),
                        attribution: attribution.clone(),
                        at: now,
                    };
                    scope.emit_user(event);
                    return Ok(BindFlow::DeniedAtPipeline {
                        stage: PipelineStage::Predicate,
                        reason,
                    });
                }

                // All stages passed — emit success
                let event = crate::audit::UserAuditEvent::CapabilityBound {
                    trace_id,
                    requester: proof_requester_did,
                    subject_repr,
                    capability: C::KIND,
                    outcome: crate::authority::BindOutcomeRepr::Success,
                    attribution,
                    at: now,
                };
                scope.emit_user(event);
                Ok(BindFlow::Success)
            })
            .await;

        // Stage 6: timing equalization (§4.6)
        let timing_target = crate::timing::equalize_timing_target_for::<C>(ctx.oracles());
        crate::timing::equalize_timing(start, timing_target).await;

        // Return
        match pipeline_result {
            Ok(BindFlow::Success) => Ok(BoundUserProof {
                proof: self,
                _life: PhantomData,
            }),
            Ok(BindFlow::DeniedAtPipeline { stage, reason }) => {
                Err(BindError::DeniedAtPipeline { stage, reason })
            }
            Err(bind_err) => Err(bind_err),
        }
    }
}

/// Bound user-class proof. The only type that grants access to
/// the wrapped subject.
#[must_use]
pub struct BoundUserProof<'p, C: UserCapability> {
    proof: UserProof<C>,
    _life: PhantomData<&'p ()>,
}

impl<'p, C: UserCapability> BoundUserProof<'p, C> {
    /// Borrow the subject the proof is bound to.
    pub fn subject(&self) -> &<C as UserCapability>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester DID.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Return the forensic trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }

    /// Re-derive a non-`Copy` borrowed handle.
    ///
    /// Re-checks expiry against [`UserCapability::MAX_AGE`]. Per
    /// §4.3 reborrow does NOT re-run oracle consultations or the
    /// capability predicate — operators wanting fresh policy
    /// checks call `bind` again on a fresh proof. Success is
    /// silent (the original bind already emitted the terminal
    /// event); failure emits a
    /// [`crate::audit::UserAuditEvent::ReborrowFailed`] and
    /// returns [`BindFailureReason::Expired`].
    ///
    /// # Errors
    ///
    /// Returns [`BindFailureReason::Expired`] when the proof has
    /// aged past `C::MAX_AGE`. Returns
    /// [`BindFailureReason::AuditUnavailable`] when the audit
    /// machinery itself fails on the `ReborrowFailed` emit.
    pub async fn reborrow<'r>(
        &'r self,
        ctx: &AuthContext<'_>,
    ) -> Result<UserProofRef<'r, C>, BindFailureReason>
    where
        <C as UserCapability>::Subject: crate::authority::HasResourceLocation,
    {
        if self.proof.issued_at.elapsed() <= C::MAX_AGE {
            // Inside window: silent success.
            return Ok(UserProofRef { proof: &self.proof });
        }

        // Past window: emit ReborrowFailed via composite_audit.
        let trace_id = self.proof.trace_id;
        let requester = self.proof.requester.clone();
        let now = std::time::SystemTime::now();
        let target_did = self.proof.subject.resource_did().clone();
        let target_nsid = self.proof.subject.resource_nsid().clone();
        let subject_repr = crate::target::TargetRepresentation::structural_only(
            crate::target::StructuralRepresentation::Resource {
                did: target_did,
                nsid: target_nsid,
            },
        );

        let audit_result: Result<(), BindError> = crate::audit::composite_audit(
            trace_id,
            ctx.audit(),
            async |scope| {
                let event = crate::audit::UserAuditEvent::ReborrowFailed {
                    trace_id,
                    requester,
                    subject_repr,
                    capability: C::KIND,
                    reason: BindFailureReason::Expired,
                    at: now,
                };
                scope.emit_user(event);
                Ok::<(), BindError>(())
            },
        )
        .await;

        match audit_result {
            Ok(()) => Err(BindFailureReason::Expired),
            // Reborrow's BindFailureReason vocabulary is narrower
            // than BindError's; collapse audit infrastructure
            // failures to AuditUnavailable.
            Err(_) => Err(BindFailureReason::AuditUnavailable),
        }
    }
}

/// Borrowed handle into a [`BoundUserProof`]. **Not `Copy`** —
/// reborrow is explicit.
pub struct UserProofRef<'p, C: UserCapability> {
    proof: &'p UserProof<C>,
}

impl<'p, C: UserCapability> UserProofRef<'p, C> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<C as UserCapability>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }
}

// ============================================================
// Channel-class proof family.
// ============================================================

/// Channel-class capability proof.
#[must_use = "an unbound ChannelProof grants no access; call .bind to use it"]
pub struct ChannelProof<E: Endpoint> {
    requester: Did,
    subject: <E as Endpoint>::Subject,
    issued_at: Instant,
    issuer: AuthorityId,
    capability_kind: CapabilityKind,
    trace_id: TraceId,
    _capability: PhantomData<E>,
    _unconstructible_outside_crate: PhantomData<sealed::Token>,
}

impl<E: Endpoint> ChannelProof<E> {
    /// Crate-internal constructor.
    pub(crate) fn new_internal(
        requester: Did,
        subject: <E as Endpoint>::Subject,
        issued_at: Instant,
        issuer: AuthorityId,
        trace_id: TraceId,
    ) -> Self {
        ChannelProof {
            requester,
            subject,
            issued_at,
            issuer,
            capability_kind: E::KIND,
            trace_id,
            _capability: PhantomData,
            _unconstructible_outside_crate: PhantomData,
        }
    }

    /// Bind. Phase 1 stub.
    pub fn bind<'p>(
        self,
        _ctx: &AuthContext<'_>,
        _target: &<E as Endpoint>::Subject,
    ) -> Result<BoundChannelProof<'p, E>, BindError>
    where
        Self: 'p,
    {
        unimplemented!("§4.3 ChannelProof::bind: Phase 4");
    }
}

/// Bound channel-class proof.
#[must_use]
pub struct BoundChannelProof<'p, E: Endpoint> {
    proof: ChannelProof<E>,
    _life: PhantomData<&'p ()>,
}

impl<'p, E: Endpoint> BoundChannelProof<'p, E> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<E as Endpoint>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }

    /// Reborrow. Phase 1 stub.
    pub fn reborrow<'r>(
        &'r self,
        _ctx: &AuthContext<'_>,
    ) -> Result<ChannelProofRef<'r, E>, BindFailureReason> {
        unimplemented!("§4.3 BoundChannelProof::reborrow: Phase 4");
    }
}

/// Borrowed handle into a [`BoundChannelProof`].
pub struct ChannelProofRef<'p, E: Endpoint> {
    proof: &'p ChannelProof<E>,
}

impl<'p, E: Endpoint> ChannelProofRef<'p, E> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<E as Endpoint>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }
}

// ============================================================
// Substrate-class proof family.
// ============================================================

/// Substrate-class capability proof. NEVER wire-shippable (§4.8 W6).
#[must_use = "an unbound SubstrateProof grants no access; call .bind to use it"]
pub struct SubstrateProof<S: SubstrateScope> {
    requester: Did,
    subject: <S as SubstrateScope>::Subject,
    issued_at: Instant,
    issuer: AuthorityId,
    capability_kind: CapabilityKind,
    trace_id: TraceId,
    _capability: PhantomData<S>,
    _unconstructible_outside_crate: PhantomData<sealed::Token>,
}

impl<S: SubstrateScope> SubstrateProof<S> {
    /// Crate-internal constructor.
    pub(crate) fn new_internal(
        requester: Did,
        subject: <S as SubstrateScope>::Subject,
        issued_at: Instant,
        issuer: AuthorityId,
        trace_id: TraceId,
    ) -> Self {
        SubstrateProof {
            requester,
            subject,
            issued_at,
            issuer,
            capability_kind: S::KIND,
            trace_id,
            _capability: PhantomData,
            _unconstructible_outside_crate: PhantomData,
        }
    }

    /// Bind. Phase 1 stub.
    pub fn bind<'p>(
        self,
        _ctx: &AuthContext<'_>,
        _target: &<S as SubstrateScope>::Subject,
    ) -> Result<BoundSubstrateProof<'p, S>, BindError>
    where
        Self: 'p,
    {
        unimplemented!("§4.3 SubstrateProof::bind: Phase 4");
    }
}

/// Bound substrate-class proof.
#[must_use]
pub struct BoundSubstrateProof<'p, S: SubstrateScope> {
    proof: SubstrateProof<S>,
    _life: PhantomData<&'p ()>,
}

impl<'p, S: SubstrateScope> BoundSubstrateProof<'p, S> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<S as SubstrateScope>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }

    /// Reborrow. Phase 1 stub.
    pub fn reborrow<'r>(
        &'r self,
        _ctx: &AuthContext<'_>,
    ) -> Result<SubstrateProofRef<'r, S>, BindFailureReason> {
        unimplemented!("§4.3 BoundSubstrateProof::reborrow: Phase 4");
    }
}

/// Borrowed handle into a [`BoundSubstrateProof`].
pub struct SubstrateProofRef<'p, S: SubstrateScope> {
    proof: &'p SubstrateProof<S>,
}

impl<'p, S: SubstrateScope> SubstrateProofRef<'p, S> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<S as SubstrateScope>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }
}

// ============================================================
// Moderation-class proof family.
// ============================================================

/// Moderation-class capability proof. NEVER wire-shippable (§4.8 W6).
#[must_use = "an unbound ModerationProof grants no access; call .bind to use it"]
pub struct ModerationProof<C: ModerationCapability> {
    requester: Did,
    subject: <C as ModerationCapability>::Subject,
    issued_at: Instant,
    issuer: AuthorityId,
    capability_kind: CapabilityKind,
    trace_id: TraceId,
    _capability: PhantomData<C>,
    _unconstructible_outside_crate: PhantomData<sealed::Token>,
}

impl<C: ModerationCapability> ModerationProof<C> {
    /// Crate-internal constructor.
    pub(crate) fn new_internal(
        requester: Did,
        subject: <C as ModerationCapability>::Subject,
        issued_at: Instant,
        issuer: AuthorityId,
        trace_id: TraceId,
    ) -> Self {
        ModerationProof {
            requester,
            subject,
            issued_at,
            issuer,
            capability_kind: C::KIND,
            trace_id,
            _capability: PhantomData,
            _unconstructible_outside_crate: PhantomData,
        }
    }

    /// Bind. Phase 1 stub.
    pub fn bind<'p>(
        self,
        _ctx: &AuthContext<'_>,
        _target: &<C as ModerationCapability>::Subject,
    ) -> Result<BoundModerationProof<'p, C>, BindError>
    where
        Self: 'p,
    {
        unimplemented!("§4.3 ModerationProof::bind: Phase 4");
    }
}

/// Bound moderation-class proof.
#[must_use]
pub struct BoundModerationProof<'p, C: ModerationCapability> {
    proof: ModerationProof<C>,
    _life: PhantomData<&'p ()>,
}

impl<'p, C: ModerationCapability> BoundModerationProof<'p, C> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<C as ModerationCapability>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }

    /// Reborrow. Phase 1 stub.
    pub fn reborrow<'r>(
        &'r self,
        _ctx: &AuthContext<'_>,
    ) -> Result<ModerationProofRef<'r, C>, BindFailureReason> {
        unimplemented!("§4.3 BoundModerationProof::reborrow: Phase 4");
    }
}

/// Borrowed handle into a [`BoundModerationProof`].
pub struct ModerationProofRef<'p, C: ModerationCapability> {
    proof: &'p ModerationProof<C>,
}

impl<'p, C: ModerationCapability> ModerationProofRef<'p, C> {
    /// Borrow the subject.
    pub fn subject(&self) -> &<C as ModerationCapability>::Subject {
        &self.proof.subject
    }

    /// Borrow the requester.
    pub fn requester(&self) -> &Did {
        &self.proof.requester
    }

    /// Trace id.
    pub fn trace_id(&self) -> TraceId {
        self.proof.trace_id
    }
}

// ============================================================
// Static assertions: forbidden derives (§4.3).
// ============================================================
//
// We assert that none of the twelve proof types implement
// `Clone`, `Default`, `Send`-as-trait-object, or `serde::Serialize`.
// `serde` is feature-gated; the Clone / Default assertions hold
// regardless.
//
// We test these with a `static_assertions`-style trick using
// trait-bound checks at the test level. The genuine compile-fail
// assertion lives in tests/.

#[cfg(test)]
mod tests {
    use super::*;

    // Negative type-trait tests are encoded via the `trybuild`
    // harness in tests/. Here we only assert that the proof types
    // can be referenced; the forbidden-derive assertion is in
    // the compile-fail tests.

    #[test]
    fn authority_id_round_trips() {
        let a = AuthorityId::from_bytes([1; 16]);
        assert_eq!(a, a);
    }

    // ========================================================
    // Phase 7d C3 — bind/reborrow shared-helper tests.
    // ========================================================

    /// §4.3 precheck: equal subject vs target → Ok; unequal → TargetMismatch.
    #[test]
    fn precheck_target_match_pins_equality() {
        let a = "subject-a";
        let b = "subject-b";
        assert!(matches!(precheck_target_match(&a, &a), Ok(())));
        assert!(matches!(
            precheck_target_match(&a, &b),
            Err(BindError::TargetMismatch)
        ));
    }

    /// §4.3 precheck: a Did-bearing proof matched against an
    /// AuthContext with the same Did → Ok. AuthContext with
    /// Anonymous → ContextMismatch (anonymous can never carry an
    /// authenticated Did).
    #[test]
    fn precheck_context_match_pins_did_comparison() {
        use crate::ingress::{AttributionChain, AuditSinks, OracleSet};
        use std::sync::Arc;

        // Minimal fixture inline (proof.rs doesn't otherwise carry
        // AuthContext fixtures — duplicate the C2 ContextFixture
        // pattern here just enough to construct a context).
        struct NoSink;
        impl crate::audit::UserAuditSink for NoSink {
            fn record(
                &self,
                _: crate::audit::UserAuditEvent,
            ) -> Result<(), crate::audit::AuditError> {
                Ok(())
            }
        }
        impl crate::audit::ChannelAuditSink for NoSink {
            fn record(
                &self,
                _: crate::audit::ChannelAuditEvent,
            ) -> Result<(), crate::audit::AuditError> {
                Ok(())
            }
        }
        impl crate::audit::SubstrateAuditSink for NoSink {
            fn record(
                &self,
                _: crate::audit::SubstrateAuditEvent,
            ) -> Result<(), crate::audit::AuditError> {
                Ok(())
            }
        }
        impl crate::audit::ModerationAuditSink for NoSink {
            fn record(
                &self,
                _: crate::audit::ModerationAuditEvent,
            ) -> Result<(), crate::audit::AuditError> {
                Ok(())
            }
        }
        impl crate::audit::FallbackAuditSink for NoSink {
            fn record_panic(
                &self,
                _: crate::audit::SinkKind,
                _: TraceId,
                _: CapabilityKind,
                _: std::time::SystemTime,
            ) {
            }
            fn record_composite_failure(
                &self,
                _: TraceId,
                _: crate::audit::CompositeOpId,
                _: &[crate::audit::SinkKind],
                _: &[crate::audit::SinkKind],
                _: std::time::SystemTime,
            ) {
            }
            fn record_event(&self, _: crate::audit::FallbackAuditEvent) {}
        }
        struct NoOracle;
        impl crate::oracle::BlockOracle for NoOracle {
            fn block_state(&self, _: &Did, _: &Did) -> crate::oracle::BlockState {
                crate::oracle::BlockState::None
            }
            fn last_synced_at(&self) -> std::time::SystemTime {
                std::time::SystemTime::UNIX_EPOCH
            }
            fn data_freshness_bound(&self) -> Duration {
                Duration::from_secs(60)
            }
            fn worst_case_latency_for(&self, _: crate::oracle::BlockOracleQuery) -> Duration {
                Duration::ZERO
            }
        }
        impl crate::oracle::AudienceOracle for NoOracle {
            fn audience_state(
                &self,
                _: &Did,
                _: &crate::authority::ResourceId,
            ) -> crate::oracle::AudienceState {
                crate::oracle::AudienceState::NoAudienceConfigured
            }
            fn last_synced_at(&self) -> std::time::SystemTime {
                std::time::SystemTime::UNIX_EPOCH
            }
            fn data_freshness_bound(&self) -> Duration {
                Duration::from_secs(60)
            }
            fn worst_case_latency_for(
                &self,
                _: crate::oracle::AudienceOracleQuery,
            ) -> Duration {
                Duration::ZERO
            }
        }
        impl crate::oracle::MuteOracle for NoOracle {
            fn mute_state(&self, _: &Did, _: &Did) -> crate::oracle::MuteState {
                crate::oracle::MuteState::None
            }
            fn last_synced_at(&self) -> std::time::SystemTime {
                std::time::SystemTime::UNIX_EPOCH
            }
            fn data_freshness_bound(&self) -> Duration {
                Duration::from_secs(60)
            }
            fn worst_case_latency_for(&self, _: crate::oracle::MuteOracleQuery) -> Duration {
                Duration::ZERO
            }
        }

        let sink: Arc<NoSink> = Arc::new(NoSink);
        let oracle: Arc<NoOracle> = Arc::new(NoOracle);
        let inspection: Arc<crate::authority::NoInspectionNotifications> =
            Arc::new(crate::authority::NoInspectionNotifications);

        let did_a = Did::new("did:plc:contextmatch-a").unwrap();
        let did_b = Did::new("did:plc:contextmatch-b").unwrap();

        let ctx_with_a = AuthContext::new_internal(
            Requester::Did(did_a.clone()),
            TraceId::from_bytes([0u8; 16]),
            AuditSinks {
                user: &*sink,
                channel: &*sink,
                substrate: &*sink,
                moderation: &*sink,
                fallback: &*sink,
                inspection_queue: &*inspection,
            },
            OracleSet {
                block: &*oracle,
                audience: &*oracle,
                mute: &*oracle,
            },
            AttributionChain::empty(),
        );

        // Match → Ok
        assert!(matches!(precheck_context_match(&did_a, &ctx_with_a), Ok(())));
        // Did mismatch → ContextMismatch
        assert!(matches!(
            precheck_context_match(&did_b, &ctx_with_a),
            Err(BindError::ContextMismatch)
        ));

        // Anonymous AuthContext → ContextMismatch regardless of proof Did
        let ctx_anon = AuthContext::new_internal(
            Requester::Anonymous,
            TraceId::from_bytes([0u8; 16]),
            AuditSinks {
                user: &*sink,
                channel: &*sink,
                substrate: &*sink,
                moderation: &*sink,
                fallback: &*sink,
                inspection_queue: &*inspection,
            },
            OracleSet {
                block: &*oracle,
                audience: &*oracle,
                mute: &*oracle,
            },
            AttributionChain::empty(),
        );
        assert!(matches!(
            precheck_context_match(&did_a, &ctx_anon),
            Err(BindError::ContextMismatch)
        ));
    }

    /// §4.3 / §4.7 precheck: a proof inside the MAX_AGE window
    /// passes; a proof with a backdated `issued_at` past the
    /// window fails closed with `BindError::Expired`.
    #[test]
    fn precheck_expired_pins_max_age_window() {
        // Inside window
        let now = Instant::now();
        assert!(matches!(
            precheck_expired(now, Duration::from_secs(60)),
            Ok(())
        ));
        // Backdated 200ms past a 100ms window → Expired
        let past = Instant::now() - Duration::from_millis(200);
        assert!(matches!(
            precheck_expired(past, Duration::from_millis(100)),
            Err(BindError::Expired)
        ));
    }

    /// Phase 7d C3: `From<CompositeAuditError> for BindError`
    /// maps audit-machinery failures to AuditUnavailable, with
    /// InconsistencyUnrecoverable mapping to AuditPanicked.
    #[test]
    fn bind_error_from_composite_audit_error_pins_mapping() {
        use crate::audit::{AuditError, CompositeAuditError, SinkKind};
        let cae_commit = CompositeAuditError::SinkCommitFailed {
            class: SinkKind::User,
            source: AuditError::Unavailable,
        };
        assert!(matches!(BindError::from(cae_commit), BindError::AuditUnavailable));

        let cae_rollback = CompositeAuditError::RollbackDispatchFailed {
            class: SinkKind::User,
            source: AuditError::Unavailable,
        };
        assert!(matches!(
            BindError::from(cae_rollback),
            BindError::AuditUnavailable
        ));

        let cae_tracker = CompositeAuditError::TrackerFull;
        assert!(matches!(BindError::from(cae_tracker), BindError::AuditUnavailable));

        let cae_unrec = CompositeAuditError::InconsistencyUnrecoverable;
        assert!(matches!(BindError::from(cae_unrec), BindError::AuditPanicked));
    }
}

// ============================================================
// Phase 7d C4-C7 — bind/reborrow test infrastructure + tests.
// ============================================================
//
// Shared mock sinks/oracles + ContextFixture used by the per-
// class bind/reborrow tests. Lives at module scope so all four
// classes' test modules can reuse it.

#[cfg(test)]
mod bind_test_fixtures {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::audit::{
        AuditError, ChannelAuditEvent, ChannelAuditSink, CompositeOpId, FallbackAuditEvent,
        FallbackAuditSink, ModerationAuditEvent, ModerationAuditSink, SinkKind,
        SubstrateAuditEvent, SubstrateAuditSink, UserAuditEvent, UserAuditSink,
    };
    use crate::authority::moderation::{
        InspectionNotification, InspectionNotificationQueueImpl,
    };
    use crate::ingress::{AttributionChain, AuditSinks, OracleSet};
    use crate::oracle::{
        AudienceOracle, AudienceOracleQuery, AudienceState, BlockOracle, BlockOracleQuery,
        BlockState, MuteOracle, MuteOracleQuery, MuteState,
    };

    // ---- Capturing audit sinks ----

    pub struct CapturingUserSink {
        captured: Mutex<Vec<UserAuditEvent>>,
    }
    impl CapturingUserSink {
        pub fn new() -> Self {
            CapturingUserSink {
                captured: Mutex::new(Vec::new()),
            }
        }
        pub fn captured(&self) -> Vec<UserAuditEvent> {
            self.captured.lock().unwrap().clone()
        }
    }
    impl UserAuditSink for CapturingUserSink {
        fn record(&self, event: UserAuditEvent) -> Result<(), AuditError> {
            self.captured.lock().unwrap().push(event);
            Ok(())
        }
    }

    pub struct CapturingChannelSink {
        captured: Mutex<Vec<ChannelAuditEvent>>,
    }
    impl CapturingChannelSink {
        pub fn new() -> Self {
            CapturingChannelSink {
                captured: Mutex::new(Vec::new()),
            }
        }
        pub fn captured(&self) -> Vec<ChannelAuditEvent> {
            self.captured.lock().unwrap().clone()
        }
    }
    impl ChannelAuditSink for CapturingChannelSink {
        fn record(&self, event: ChannelAuditEvent) -> Result<(), AuditError> {
            self.captured.lock().unwrap().push(event);
            Ok(())
        }
    }

    pub struct CapturingSubstrateSink {
        captured: Mutex<Vec<SubstrateAuditEvent>>,
    }
    impl CapturingSubstrateSink {
        pub fn new() -> Self {
            CapturingSubstrateSink {
                captured: Mutex::new(Vec::new()),
            }
        }
        pub fn captured(&self) -> Vec<SubstrateAuditEvent> {
            self.captured.lock().unwrap().clone()
        }
    }
    impl SubstrateAuditSink for CapturingSubstrateSink {
        fn record(&self, event: SubstrateAuditEvent) -> Result<(), AuditError> {
            self.captured.lock().unwrap().push(event);
            Ok(())
        }
    }

    pub struct CapturingModerationSink {
        captured: Mutex<Vec<ModerationAuditEvent>>,
    }
    impl CapturingModerationSink {
        pub fn new() -> Self {
            CapturingModerationSink {
                captured: Mutex::new(Vec::new()),
            }
        }
        pub fn captured(&self) -> Vec<ModerationAuditEvent> {
            self.captured.lock().unwrap().clone()
        }
    }
    impl ModerationAuditSink for CapturingModerationSink {
        fn record(&self, event: ModerationAuditEvent) -> Result<(), AuditError> {
            self.captured.lock().unwrap().push(event);
            Ok(())
        }
    }

    pub struct NoopFallback;
    impl FallbackAuditSink for NoopFallback {
        fn record_panic(
            &self,
            _: SinkKind,
            _: TraceId,
            _: CapabilityKind,
            _: SystemTime,
        ) {
        }
        fn record_composite_failure(
            &self,
            _: TraceId,
            _: CompositeOpId,
            _: &[SinkKind],
            _: &[SinkKind],
            _: SystemTime,
        ) {
        }
        fn record_event(&self, _: FallbackAuditEvent) {}
    }

    // ---- Capturing inspection-notification queue (for C7
    //      moderation tests) ----

    pub struct CapturingInspection {
        captured: Mutex<Vec<(Did, InspectionNotification)>>,
    }
    impl CapturingInspection {
        pub fn new() -> Self {
            CapturingInspection {
                captured: Mutex::new(Vec::new()),
            }
        }
        pub fn captured(&self) -> Vec<(Did, InspectionNotification)> {
            self.captured.lock().unwrap().clone()
        }
    }
    impl InspectionNotificationQueueImpl for CapturingInspection {
        fn enqueue(&self, owner: &Did, event: InspectionNotification) {
            self.captured
                .lock()
                .unwrap()
                .push((owner.clone(), event));
        }
    }

    // ---- Configurable block oracle ----

    pub struct ConfigurableBlockOracle {
        pub state: BlockState,
    }
    impl BlockOracle for ConfigurableBlockOracle {
        fn block_state(&self, _: &Did, _: &Did) -> BlockState {
            self.state.clone()
        }
        fn last_synced_at(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
        fn data_freshness_bound(&self) -> Duration {
            Duration::from_secs(60)
        }
        fn worst_case_latency_for(&self, _: BlockOracleQuery) -> Duration {
            Duration::ZERO
        }
    }

    pub struct NoopAudienceOracle;
    impl AudienceOracle for NoopAudienceOracle {
        fn audience_state(
            &self,
            _: &Did,
            _: &crate::authority::ResourceId,
        ) -> AudienceState {
            AudienceState::NoAudienceConfigured
        }
        fn last_synced_at(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
        fn data_freshness_bound(&self) -> Duration {
            Duration::from_secs(60)
        }
        fn worst_case_latency_for(&self, _: AudienceOracleQuery) -> Duration {
            Duration::ZERO
        }
    }

    pub struct NoopMuteOracle;
    impl MuteOracle for NoopMuteOracle {
        fn mute_state(&self, _: &Did, _: &Did) -> MuteState {
            MuteState::None
        }
        fn last_synced_at(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
        fn data_freshness_bound(&self) -> Duration {
            Duration::from_secs(60)
        }
        fn worst_case_latency_for(&self, _: MuteOracleQuery) -> Duration {
            Duration::ZERO
        }
    }

    /// Owned bundle holding all sink/oracle/inspection state.
    /// Hands out borrowed [`AuthContext`] values per requester
    /// variant + per block-state.
    pub struct BindFixture {
        pub user: Arc<CapturingUserSink>,
        pub channel: Arc<CapturingChannelSink>,
        pub substrate: Arc<CapturingSubstrateSink>,
        pub moderation: Arc<CapturingModerationSink>,
        pub fallback: Arc<NoopFallback>,
        pub inspection: Arc<CapturingInspection>,
        pub block: Arc<ConfigurableBlockOracle>,
        pub audience: Arc<NoopAudienceOracle>,
        pub mute: Arc<NoopMuteOracle>,
    }

    impl BindFixture {
        pub fn new() -> Self {
            BindFixture {
                user: Arc::new(CapturingUserSink::new()),
                channel: Arc::new(CapturingChannelSink::new()),
                substrate: Arc::new(CapturingSubstrateSink::new()),
                moderation: Arc::new(CapturingModerationSink::new()),
                fallback: Arc::new(NoopFallback),
                inspection: Arc::new(CapturingInspection::new()),
                block: Arc::new(ConfigurableBlockOracle {
                    state: BlockState::None,
                }),
                audience: Arc::new(NoopAudienceOracle),
                mute: Arc::new(NoopMuteOracle),
            }
        }

        pub fn with_block_state(state: BlockState) -> Self {
            let mut f = Self::new();
            f.block = Arc::new(ConfigurableBlockOracle { state });
            f
        }

        pub fn build_ctx(&self, requester: Requester) -> AuthContext<'_> {
            AuthContext::new_internal(
                requester,
                TraceId::from_bytes([0xCD; 16]),
                AuditSinks {
                    user: &*self.user,
                    channel: &*self.channel,
                    substrate: &*self.substrate,
                    moderation: &*self.moderation,
                    fallback: &*self.fallback,
                    inspection_queue: &*self.inspection,
                },
                OracleSet {
                    block: &*self.block,
                    audience: &*self.audience,
                    mute: &*self.mute,
                },
                AttributionChain::empty(),
            )
        }
    }

    pub fn sample_did() -> Did {
        Did::new("did:plc:phase7dbind").unwrap()
    }

    pub fn sample_did_other() -> Did {
        Did::new("did:plc:phase7dother").unwrap()
    }

    pub fn sample_resource_id() -> crate::authority::ResourceId {
        crate::authority::ResourceId::new(
            sample_did(),
            crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            crate::proto::Rkey::new("3jzfcijpj2z2a").unwrap(),
        )
    }
}

// ========================================================
// Phase 7d C4 — UserProof::bind + BoundUserProof::reborrow tests.
// ========================================================

#[cfg(test)]
mod user_bind_tests {
    use super::bind_test_fixtures::*;
    use super::*;
    use crate::audit::UserAuditEvent;
    use crate::authority::v1::{ParticipatePrivate, ViewPrivate};
    use crate::authority::{issue_user, BindOutcomeRepr, CapabilityClass, CapabilityKind};
    use crate::oracle::{BlockOracleQuery, BlockState};
    use std::time::Duration;

    /// Helper: issue a UserProof<ViewPrivate> via the Phase 7c
    /// chokepoint so the resulting proof carries the same
    /// trace_id/requester/issuer the bind path expects.
    fn issue_view_private_for(
        ctx: &AuthContext<'_>,
        subject: crate::authority::ResourceId,
    ) -> UserProof<ViewPrivate> {
        match issue_user::<ViewPrivate>(ctx, subject) {
            Ok(p) => p,
            Err(_) => panic!("issuance prerequisite failed"),
        }
    }

    /// §4.3 happy path: Did requester + clean oracle state → bind
    /// returns Ok(BoundUserProof). One CapabilityBound event
    /// captured with outcome Success.
    #[tokio::test]
    async fn bind_succeeds_with_did_requester_and_clean_state() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        let r = proof.bind(&ctx, &sample_resource_id()).await;
        assert!(r.is_ok(), "happy path bind should succeed");

        let captured = fixture.user.captured();
        assert_eq!(captured.len(), 1, "exactly one terminal audit event");
        match &captured[0] {
            UserAuditEvent::CapabilityBound {
                capability,
                outcome,
                ..
            } => {
                assert_eq!(*capability, CapabilityKind::ViewPrivate);
                assert!(matches!(outcome, BindOutcomeRepr::Success));
            }
            other => panic!("expected CapabilityBound, got {other:?}"),
        }
    }

    /// §4.3 precondition: target ≠ proof.subject → TargetMismatch
    /// (no audit emit, no stages run).
    #[tokio::test]
    async fn bind_rejects_target_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        // Different subject than what the proof was issued for
        let different_target = crate::authority::ResourceId::new(
            sample_did_other(),
            crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            crate::proto::Rkey::new("3jzfcijpj2z2a").unwrap(),
        );
        let r = proof.bind(&ctx, &different_target).await;
        match r {
            Err(BindError::TargetMismatch) => {}
            Err(other) => panic!("expected TargetMismatch, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
        assert_eq!(
            fixture.user.captured().len(),
            0,
            "precondition failure does not emit audit"
        );
    }

    /// §4.3 precondition: AuthContext requester ≠ proof.requester
    /// → ContextMismatch (no audit emit).
    #[tokio::test]
    async fn bind_rejects_context_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let ctx_a = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx_a, sample_resource_id());

        // Bind with a different AuthContext (different Did)
        let ctx_b = fixture.build_ctx(Requester::Did(sample_did_other()));
        let r = proof.bind(&ctx_b, &sample_resource_id()).await;
        assert!(matches!(r, Err(BindError::ContextMismatch)));
        assert_eq!(fixture.user.captured().len(), 0);
    }

    /// §4.3 / §4.7 precondition: a backdated proof past MAX_AGE
    /// fails closed at precheck_expired (no audit emit). Uses
    /// ParticipatePrivate (MAX_AGE = 60s) and shifts issued_at
    /// 200s into the past via direct UserProof::new_internal —
    /// the issue_user chokepoint always returns a fresh Instant
    /// so we bypass it here.
    #[tokio::test]
    async fn bind_rejects_expired_at_precondition() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));

        // Construct a backdated proof directly (test-only path).
        let backdated_proof = UserProof::<ParticipatePrivate>::new_internal(
            sample_did(),
            sample_resource_id(),
            Instant::now() - Duration::from_secs(200),
            AuthorityId::from_bytes([0u8; 16]),
            TraceId::from_bytes([0xCD; 16]),
        );
        let r = backdated_proof.bind(&ctx, &sample_resource_id()).await;
        assert!(matches!(r, Err(BindError::Expired)));
        assert_eq!(fixture.user.captured().len(), 0);
    }

    /// §4.3 stage 2 — BlockConsultation: bind against a blocked
    /// requester→owner pair returns DeniedAtPipeline at the
    /// BlockConsultation stage with a Blocked DenialReason.
    /// Forensic-ordering: failure surfaces at BlockConsultation,
    /// not at Predicate.
    #[tokio::test]
    async fn bind_denied_at_block_consultation_when_oracle_returns_blocked() {
        let fixture = BindFixture::with_block_state(BlockState::Mutual);
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        let r = proof.bind(&ctx, &sample_resource_id()).await;
        let Err(err) = r else {
            panic!("expected Err, got Ok");
        };
        match err {
            BindError::DeniedAtPipeline { stage, reason } => {
                assert_eq!(stage, PipelineStage::BlockConsultation);
                match reason {
                    DenialReason::Blocked { query, state } => {
                        assert_eq!(query, BlockOracleQuery::RequesterVsResourceOwner);
                        assert!(matches!(state, BlockState::Mutual));
                    }
                    other => panic!("expected Blocked, got {other:?}"),
                }
            }
            other => panic!("expected DeniedAtPipeline(BlockConsultation), got {other:?}"),
        }

        // Audit emit fires the denial event (CapabilityIssuanceDenied),
        // not the success event.
        let captured = fixture.user.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            UserAuditEvent::CapabilityIssuanceDenied { reason, .. } => {
                assert!(matches!(reason, DenialReason::Blocked { .. }));
            }
            other => panic!("expected CapabilityIssuanceDenied, got {other:?}"),
        }
    }

    /// §4.3 reborrow: a BoundUserProof inside MAX_AGE re-derives a
    /// silent ProofRef. No audit emit on success (the original bind
    /// already emitted the terminal event).
    #[tokio::test]
    async fn reborrow_succeeds_within_max_age() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        let bound = match proof.bind(&ctx, &sample_resource_id()).await {
            Ok(b) => b,
            Err(_) => panic!("bind prerequisite failed"),
        };
        let captured_after_bind = fixture.user.captured().len();

        let r = bound.reborrow(&ctx).await;
        assert!(r.is_ok(), "reborrow within MAX_AGE should succeed");
        assert_eq!(
            fixture.user.captured().len(),
            captured_after_bind,
            "successful reborrow is silent (no audit emit)"
        );
    }

    /// §4.3 reborrow: a BoundUserProof past MAX_AGE returns
    /// Expired and emits a ReborrowFailed audit event (composite-
    /// audit single-emit).
    #[tokio::test]
    async fn reborrow_returns_expired_past_max_age_and_emits_event() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));

        // Construct a backdated bound proof directly (test-only).
        // ParticipatePrivate has MAX_AGE = 60s; backdate 100s.
        let backdated = UserProof::<ParticipatePrivate>::new_internal(
            sample_did(),
            sample_resource_id(),
            Instant::now() - Duration::from_secs(100),
            AuthorityId::from_bytes([0u8; 16]),
            TraceId::from_bytes([0xCD; 16]),
        );
        let bound = BoundUserProof {
            proof: backdated,
            _life: PhantomData,
        };

        let r = bound.reborrow(&ctx).await;
        assert!(matches!(r, Err(BindFailureReason::Expired)));

        let captured = fixture.user.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            UserAuditEvent::ReborrowFailed { reason, .. } => {
                assert!(matches!(reason, BindFailureReason::Expired));
            }
            other => panic!("expected ReborrowFailed, got {other:?}"),
        }
    }

    /// §4.3 reborrow discipline: reborrow does NOT re-consult
    /// oracles. Block the subject AFTER bind succeeds — reborrow
    /// within MAX_AGE still succeeds because oracles aren't
    /// re-consulted. This pins that operators wanting fresh policy
    /// checks must call bind again on a fresh proof.
    #[tokio::test]
    async fn reborrow_does_not_re_consult_oracles() {
        // Bind under clean state
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());
        let bound = match proof.bind(&ctx, &sample_resource_id()).await {
            Ok(b) => b,
            Err(_) => panic!("bind prerequisite failed"),
        };

        // After bind, operator "blocks" the subject by swapping the
        // oracle. Build a fresh fixture with a Mutual block state.
        let blocked_fixture = BindFixture::with_block_state(BlockState::Mutual);
        let blocked_ctx = blocked_fixture.build_ctx(Requester::Did(sample_did()));

        // Reborrow with the now-blocked context — should still
        // succeed because reborrow doesn't re-check oracles.
        let r = bound.reborrow(&blocked_ctx).await;
        assert!(
            r.is_ok(),
            "reborrow within MAX_AGE succeeds even with blocked oracle (oracles not re-consulted)"
        );
    }

    // Pin a class-discriminator constant so 7e/7f code that
    // dispatches on CapabilityClass for user-class bind has a
    // compile-time anchor. (Cheap, prevents a future variant
    // rename from silently breaking the bind dispatch.)
    #[test]
    fn user_class_discriminator_pinned() {
        assert_eq!(
            CapabilityKind::ViewPrivate.class(),
            CapabilityClass::User
        );
    }
}

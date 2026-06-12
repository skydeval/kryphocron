// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.3 capability proof types — four parallel families with
//! wired bind + reborrow pipelines.
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
//! ## Bind pipeline (§4.3)
//!
//! Each `*Proof::bind` is `async fn` (the §4.3 pipeline runs
//! inside [`crate::audit::composite_audit`] which is async). The general
//! shape:
//!
//! 1. **Pre-checks** (no audit emit): target match, context
//!    match, expiry. Caller errors fail fast via
//!    [`BindError::TargetMismatch`] / [`BindError::ContextMismatch`]
//!    / [`BindError::Expired`].
//! 2. **Stage 0 — DeprecationGate** (Write-semantics user-class +
//!    moderation-class): consults
//!    [`crate::KRYPHOCRON_LEXICON_REGISTRY`] for the subject's
//!    NSID via [`crate::HasResourceLocation`]. Channel and
//!    substrate skip (their subjects carry no NSID).
//! 3. **Stage 2 — BlockConsultation** (user-class only): consults
//!    [`crate::oracle::BlockOracle`] for the universal
//!    `RequesterVsResourceOwner` query. Multi-query consultations
//!    defer to a v0.2 per-capability oracle-results-builder
//!    trait. Channel / substrate / moderation skip — their
//!    capability traits don't declare `ORACLE_CONSULTATIONS`.
//! 4. **Stage 5 — Predicate** (user-class only): invokes
//!    [`crate::IssuancePolicy::capability_predicate`] with
//!    default-initialized oracle results (v0.1 stub per the
//!    stage-2 gap above).
//! 5. **Stage 5' — Audit emit**: emits the class-discriminating
//!    `*Bound` variant on success or `*IssuanceDenied` on stage
//!    failure via [`crate::audit::composite_audit`]. The op closure
//!    always returns `Ok(BindFlow::*)` so denial events get
//!    committed (composite_audit drops queued events on `Err`
//!    return); the bind body unpacks `BindFlow` outside the
//!    closure to surface [`BindError::DeniedAtPipeline`].
//! 6. **Stage 6 — Timing equalization** (user-class only): post-
//!    emit, sleeps until `equalize_timing_target_for::<C>`
//!    elapses (closes the §4.6 timing-channel gap).
//! 7. **Inspection-queue emit (moderation only,
//!    post-composite-audit)**: on success, fans an
//!    [`crate::InspectionNotification`] to the resource owner's
//!    queue. **OUTSIDE composite-rollback semantics** per §6.7.
//!
//! ## Reborrow pipeline (§4.3)
//!
//! Each `Bound*Proof::reborrow` is `async fn`. Re-checks expiry
//! against the capability's `MAX_AGE`. Per §4.3 reborrow does
//! **NOT** re-run oracle consultations or the capability
//! predicate — operators wanting fresh policy checks call `bind`
//! again on a fresh proof.
//!
//! - Inside window: silent success.
//! - Past window (user/channel): emits `ReborrowFailed` /
//!   `ChannelReborrowFailed`.
//! - Past window (substrate): emits `ScopeBound{outcome: Expired}`
//!   (no dedicated reborrow-failed variant; reuses success-path
//!   variant with non-Success outcome).
//! - Past window (moderation): silent at the audit layer (no
//!   suitable variant; v0.2 enrichment for emit symmetry).
//!
//! ## V0.1 audit-detail gaps
//!
//! Some audit-event fields ship as placeholders pending v0.2
//! sealed-trait infrastructure for generic data extraction from
//! the typed `Subject` / `OracleResults`:
//!
//! - User-class oracle consultations: only the universal
//!   `RequesterVsResourceOwner` block query is consulted; multi-
//!   query consultations defer to a v0.2 per-capability
//!   oracle-results-builder.
//! - Channel-class peer + session_id: synthesized from the
//!   proof's recorded Did + zero placeholders. Real extraction
//!   needs a sealed `ChannelSubjectShape` trait.
//! - Substrate-class scope_repr: ships with placeholder
//!   `ScopeKind::Shard`. Real extraction needs a sealed
//!   `HasScopeKind` trait.
//! - Moderation-class case: ships with placeholder
//!   `ModerationCaseId([0; 16])`. Real extraction needs a sealed
//!   `HasModerationCase` trait.
//!
//! All four gaps share the same shape ("the typed Subject
//! doesn't expose its fields generically; need a sealed
//! per-class extraction trait") and enrichment in v0.2.
//!
//! ## Module-level `#![allow(dead_code)]`
//!
//! The `issuer: AuthorityId` and `capability_kind: CapabilityKind`
//! fields on each `*Proof` are unread inside the crate today —
//! they carry forensic-correlation data stored for the
//! `Bound*Proof::issuer()` and `Bound*Proof::capability_kind()`
//! accessor methods that v0.2 will ship for substrate code that
//! holds bound proofs across operations. The allow stays until
//! those accessors land.
#![allow(dead_code)]

use core::marker::PhantomData;
use std::time::{Duration, Instant};

use crate::authority::capability::{
    CapabilityKind, Endpoint, ModerationCapability, OracleResultsForCapability, SubstrateScope,
    UserCapability,
};
use crate::authority::predicate::{BindError, BindFailureReason, DenialReason, PipelineStage};
use crate::authority::subjects::HasResourceLocation;
use crate::identity::TraceId;
use crate::ingress::{AuthContext, Requester};
use crate::proto::Did;
use crate::sealed;

// ============================================================
// §4.3 bind/reborrow shared helpers + BindFlow.
// ============================================================

/// §4.3 bind-pipeline outcome carried via [`crate::audit::composite_audit`]'s
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
    /// A stage-3 audience-oracle freshness commitment was past its
    /// bound. The `CapabilityBound { outcome: OracleStale }` audit
    /// event already emitted inside the closure (the stale outcome
    /// has no `DenialReason`, so it is recorded as a non-success
    /// bind outcome rather than a `CapabilityIssuanceDenied`); the
    /// bind body surfaces [`BindError::OracleStale`] to the caller.
    OracleStale {
        oracle: crate::oracle::OracleKind,
        query: crate::oracle::OracleQueryKind,
    },
}

// ============================================================
// Pre-check timing-bypass invariant (§4.3 / §4.6).
//
// The three `precheck_*` functions below run on the fail-fast
// fast path that precedes `composite_audit` and `equalize_timing`
// in the bind pipeline. They MUST consult only data the caller
// already supplied (the proof itself, the target argument, the
// AuthContext's resolved requester, the clock). If a future
// revision needs to consult secret state (resource-owner allow
// lists, audience membership, encrypted-record subject DIDs,
// any oracle whose freshness or shape depends on data the
// caller did not supply), it MUST move into the post-
// equalization portion of the pipeline — otherwise its
// per-input latency variance leaks the secret through the
// §4.6 timing channel.
//
// This is the same invariant the §4.3 stage-numbering
// discipline encodes: stage 1 (requester authority) and
// stage 4 (target match) consult caller-supplied evidence;
// stage 2 (subject ownership), stage 3 (audience), stage 5
// (oracle consultation) require equalization because they
// touch substrate-side state.
// ============================================================

/// §4.3 precheck: the proof's `subject` must equal the bind-call
/// `target`. Fail-fast precondition; runs before composite_audit
/// and emits no audit (a target mismatch is a caller error, not a
/// pipeline denial).
///
/// **Timing-bypass invariant:** see the module-level note above
/// the precheck block — must not consult secret state.
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
///
/// **Timing-bypass invariant:** see the module-level note above
/// the precheck block — must not consult secret state.
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
///
/// **Timing-bypass invariant:** see the module-level note above
/// the precheck block — must not consult secret state.
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
    /// per §4.3 / §4.9 A1 invariant via [`crate::audit::composite_audit`].
    /// On success returns [`BoundUserProof`]; on any non-success
    /// outcome the audit emit fires first and `Err(BindError)` is
    /// returned.
    ///
    /// Pipeline (v0.1):
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
        let oracles_audience = ctx.oracles().audience;
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

                // Stage 3: AudienceConsultation (§4.5).
                //
                // Consult the audience oracle for each declared query. Only
                // record-subject capabilities (ViewPrivate /
                // ParticipatePrivate / EditPrivatePost) declare audience
                // queries; for them `resource_id()` is `Some`. A non-
                // `InAudience` result denies inline here (§11) — mirroring
                // the stage-2 block deny — so the denial is forensically
                // attributed to AudienceConsultation, not pushed down to the
                // predicate. `Some(NotInAudience)` and
                // `Some(NoAudienceConfigured)` both fail closed (Decision B).
                // On `InAudience`, populate the result so the stage-5
                // predicate sees `Some(InAudience)`; the predicate's `None`
                // arm remains the type-state backstop for the structurally-
                // impossible unconsulted case (defense in depth, not an
                // alternative denial path). Without this stage the audience
                // field stayed at its default and the read-authorization
                // witness was semantically hollow.
                //
                // Timing: like the stage-2 block consultation above, this
                // touches substrate-side secret state (audience
                // membership) but runs inside the audited closure, ahead
                // of the single §4.6 `equalize_timing` below — so its
                // per-input latency variance is masked. The number of
                // queries is a per-capability compile-time constant, so
                // the call count is not data-dependent. (Block freshness
                // is not yet checked at stage 2; that pre-existing gap is
                // tracked separately.)
                let mut oracle_results =
                    <<C as UserCapability>::OracleResults as Default>::default();
                for &query in C::ORACLE_CONSULTATIONS.audience {
                    let Some(resource) = target.resource_id() else {
                        // A non-record subject that nonetheless declares an
                        // audience query is a contradiction; leave the
                        // field at its fail-closed `None` and let the
                        // stage-5 predicate backstop deny.
                        continue;
                    };
                    let sync_age = now
                        .duration_since(oracles_audience.last_synced_at())
                        .unwrap_or(Duration::ZERO);
                    if sync_age > oracles_audience.data_freshness_bound() {
                        let oracle = crate::oracle::OracleKind::Audience;
                        let query_kind = crate::oracle::OracleQueryKind::Audience(query);
                        let event = crate::audit::UserAuditEvent::CapabilityBound {
                            trace_id,
                            requester: proof_requester_did.clone(),
                            subject_repr: subject_repr.clone(),
                            capability: C::KIND,
                            outcome: crate::authority::BindOutcomeRepr::OracleStale {
                                oracle,
                                query: query_kind,
                                sync_age,
                            },
                            attribution: attribution.clone(),
                            at: now,
                        };
                        scope.emit_user(event);
                        return Ok(BindFlow::OracleStale {
                            oracle,
                            query: query_kind,
                        });
                    }
                    let state =
                        oracles_audience.audience_state(&proof_requester_did, resource);
                    if !matches!(state, crate::oracle::AudienceState::InAudience) {
                        let reason = DenialReason::NotInAudience { query, state };
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
                            stage: PipelineStage::AudienceConsultation,
                            reason,
                        });
                    }
                    oracle_results.set_audience(query, state);
                }

                // Stage 5: Predicate
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
            Ok(BindFlow::OracleStale { oracle, query }) => {
                Err(BindError::OracleStale { oracle, query })
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

    /// Bind the channel proof against a target.
    ///
    /// Consumes `self`. Pipeline (v0.1):
    /// - **Pre-checks** (no audit): target match, context match,
    ///   expiry.
    /// - **Stage 5 — Audit emit**: emits
    ///   [`crate::audit::ChannelAuditEvent::ChannelBound`] with
    ///   `outcome: BindOutcomeRepr::Success` via composite_audit.
    ///   Channel-class skips stage 0 (ChannelBinding has no NSID),
    ///   stages 2-4 (Endpoint trait has no ORACLE_CONSULTATIONS or
    ///   IssuancePolicy), and stage 6 timing equalization
    ///   (`equalize_timing_target_for` is `<C: UserCapability>`-bounded).
    ///   The §4.6 timing channel for channel-class bind is
    ///   structurally narrower (no oracle latency to mask); v0.1
    ///   defers a per-class equalization helper to v0.2.
    ///
    /// `session_digest` for the audit event is computed via
    /// [`crate::SessionDigest::compute`] using the
    /// [`crate::ingress::AuditSinks::correlation_key`].
    ///
    /// # Errors
    ///
    /// Returns precondition errors ([`BindError::TargetMismatch`] /
    /// [`BindError::ContextMismatch`] / [`BindError::Expired`])
    /// without audit emit. Returns
    /// [`BindError::AuditUnavailable`] /
    /// [`BindError::AuditPanicked`] on audit-machinery failure.
    ///
    /// **No `DeniedAtPipeline` outcomes in v0.1** — channel-class
    /// has no stages between preconditions and emit. Operator-
    /// installable channel-policy denial is a v0.2 surface.
    pub async fn bind<'p>(
        self,
        ctx: &AuthContext<'_>,
        target: &<E as Endpoint>::Subject,
    ) -> Result<BoundChannelProof<'p, E>, BindError>
    where
        Self: 'p,
        <E as Endpoint>::Subject: PartialEq,
    {
        precheck_target_match(&self.subject, target)?;
        precheck_context_match(&self.requester, ctx)?;
        precheck_expired(self.issued_at, E::MAX_AGE)?;

        // Channel subjects (ChannelBinding) carry the peer
        // ServiceIdentity directly; extract for the audit event.
        // This downcast is sound only when E::Subject is
        // ChannelBinding — v1's only Endpoint impls
        // (EmitToSyncChannel, AppViewSync, GraphSync) all use
        // ChannelBinding as Subject.
        //
        // For v0.1 we need a way to extract (peer, session_id)
        // from a generic E::Subject. The cleanest path is a sealed
        // ChannelSubjectShape trait paralleling HasResourceLocation
        // — but that's another foundation surface. v0.1 ships a
        // direct cast via Any-style downcast wrapped in the
        // capability-marker invariant. In practice, the v1
        // capability_marker! macro hard-codes
        // `Subject = ChannelBinding`; if a future Endpoint impl
        // uses a different Subject type, this code path needs the
        // sealed trait.
        //
        // For 7d we punt on the trait surface and use an unsafe-
        // free approach: add the sealed trait as a v0.2 enrichment;
        // ship the audit event with a placeholder peer + session
        // digest derived from the proof's recorded Did + a
        // synthesized session id for v0.1.
        //
        // This is an intentional v0.1 audit-surface gap documented
        // in the completion report: channel bind audit emits with
        // peer = synthesized-from-Did, session_digest = computed
        // from a placeholder session_id. The composite_audit
        // emission semantics are exercised; the audit-event
        // forensic detail is degraded.

        let trace_id = self.trace_id;
        let proof_requester_did = self.requester.clone();
        let now = std::time::SystemTime::now();

        // v0.1: synthesize a peer ServiceIdentity from the proof's
        // recorded Did. v0.2 enrichment: extract real peer from
        // Subject via a sealed `ChannelSubjectShape` trait.
        let peer_placeholder = crate::identity::ServiceIdentity::new_internal(
            proof_requester_did.clone(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        );
        // v0.1: synthesize a session id placeholder. v0.2 enrichment:
        // extract real session_id from Subject via the same sealed
        // trait above.
        let session_id_placeholder =
            crate::identity::SessionId::from_bytes([0u8; 32]);
        let session_digest = crate::identity::SessionDigest::compute(
            &session_id_placeholder,
            ctx.audit().correlation_key,
        );

        let _ = target; // v0.1: target validated by precheck_target_match only

        let pipeline_result: Result<BindFlow, BindError> =
            crate::audit::composite_audit(trace_id, ctx.audit(), async |scope| {
                let event = crate::audit::ChannelAuditEvent::ChannelBound {
                    trace_id,
                    peer: peer_placeholder,
                    session_digest,
                    endpoint: E::KIND,
                    outcome: crate::authority::BindOutcomeRepr::Success,
                    payload_completeness: crate::audit::PayloadCompleteness::PartialV01,
                    at: now,
                };
                scope.emit_channel(event);
                Ok(BindFlow::Success)
            })
            .await;

        match pipeline_result {
            Ok(BindFlow::Success) => Ok(BoundChannelProof {
                proof: self,
                _life: PhantomData,
            }),
            Ok(BindFlow::DeniedAtPipeline { stage, reason }) => {
                Err(BindError::DeniedAtPipeline { stage, reason })
            }
            Ok(BindFlow::OracleStale { oracle, query }) => {
                Err(BindError::OracleStale { oracle, query })
            }
            Err(bind_err) => Err(bind_err),
        }
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

    /// Re-derive a non-`Copy` channel borrow.
    ///
    /// Re-checks expiry against [`Endpoint::MAX_AGE`]. Per §4.3
    /// reborrow does NOT re-run channel-policy checks — operators
    /// wanting fresh checks call `bind` again on a fresh proof.
    /// Success is silent; failure emits
    /// [`crate::audit::ChannelAuditEvent::ChannelReborrowFailed`]
    /// and returns [`BindFailureReason::Expired`].
    pub async fn reborrow<'r>(
        &'r self,
        ctx: &AuthContext<'_>,
    ) -> Result<ChannelProofRef<'r, E>, BindFailureReason> {
        if self.proof.issued_at.elapsed() <= E::MAX_AGE {
            return Ok(ChannelProofRef { proof: &self.proof });
        }

        let trace_id = self.proof.trace_id;
        let now = std::time::SystemTime::now();
        // Same v0.1 placeholder approach as bind() — see the
        // ChannelProof::bind rustdoc and the completion report.
        let peer_placeholder = crate::identity::ServiceIdentity::new_internal(
            self.proof.requester.clone(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        );
        let session_id_placeholder =
            crate::identity::SessionId::from_bytes([0u8; 32]);
        let session_digest = crate::identity::SessionDigest::compute(
            &session_id_placeholder,
            ctx.audit().correlation_key,
        );

        let audit_result: Result<(), BindError> = crate::audit::composite_audit(
            trace_id,
            ctx.audit(),
            async |scope| {
                let event = crate::audit::ChannelAuditEvent::ChannelReborrowFailed {
                    trace_id,
                    peer: peer_placeholder,
                    session_digest,
                    endpoint: E::KIND,
                    reason: BindFailureReason::Expired,
                    payload_completeness: crate::audit::PayloadCompleteness::PartialV01,
                    at: now,
                };
                scope.emit_channel(event);
                Ok::<(), BindError>(())
            },
        )
        .await;

        match audit_result {
            Ok(()) => Err(BindFailureReason::Expired),
            Err(_) => Err(BindFailureReason::AuditUnavailable),
        }
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

    /// Bind the substrate proof against a scope target.
    ///
    /// Consumes `self`. Pipeline (v0.1):
    /// - **Pre-checks** (no audit): target match, context match,
    ///   expiry.
    /// - **Service-only enforcement**: substrate bind requires
    ///   the AuthContext requester be [`Requester::Service`] (per
    ///   §4.6 read-everything-authority discipline + the §4.3
    ///   issuance gate). If somehow precheck_context_match passed
    ///   but the requester is a Did, returns
    ///   [`BindError::ContextMismatch`] (defense in depth).
    /// - **Stage 5 — Audit emit**: emits
    ///   [`crate::audit::SubstrateAuditEvent::ScopeBound`] with
    ///   `outcome: BindOutcomeRepr::Success` via composite_audit.
    ///   Substrate-class skips stages 0/2-4 (no NSID, no oracles,
    ///   no predicate per §4.6) and stage 6 timing equalization.
    ///
    /// V0.1 audit-detail gap: scope_repr ships with placeholder
    /// `ScopeKind::Shard` regardless of the actual ScopeSelector
    /// variant. Real extraction needs a sealed `HasScopeKind`
    /// trait paralleling HasResourceLocation — v0.2 enrichment.
    ///
    /// # Errors
    ///
    /// Returns precondition errors without audit emit. Returns
    /// [`BindError::AuditUnavailable`] / [`BindError::AuditPanicked`]
    /// on audit-machinery failure.
    pub async fn bind<'p>(
        self,
        ctx: &AuthContext<'_>,
        target: &<S as SubstrateScope>::Subject,
    ) -> Result<BoundSubstrateProof<'p, S>, BindError>
    where
        Self: 'p,
        <S as SubstrateScope>::Subject: PartialEq,
    {
        precheck_target_match(&self.subject, target)?;
        precheck_context_match(&self.requester, ctx)?;
        precheck_expired(self.issued_at, S::MAX_AGE)?;

        // Substrate-class is Service-only (§4.6 + the §4.3
        // issuance gate). Extract ServiceIdentity from
        // AuthContext for the audit event's `service` field.
        let service = match ctx.requester() {
            Requester::Service(svc) => svc.clone(),
            _ => return Err(BindError::ContextMismatch),
        };

        let trace_id = self.trace_id;
        let now = std::time::SystemTime::now();

        // V0.1 placeholder: ScopeKind::Shard regardless of variant.
        // v0.2 enrichment: introduce HasScopeKind sealed trait.
        let scope_repr = crate::target::TargetRepresentation::structural_only(
            crate::target::StructuralRepresentation::Scope {
                kind: crate::target::ScopeKind::Shard,
            },
        );

        let _ = target; // validated by precheck_target_match

        let pipeline_result: Result<BindFlow, BindError> =
            crate::audit::composite_audit(trace_id, ctx.audit(), async |scope| {
                let event = crate::audit::SubstrateAuditEvent::ScopeBound {
                    trace_id,
                    service,
                    scope_repr,
                    capability: S::KIND,
                    outcome: crate::authority::BindOutcomeRepr::Success,
                    payload_completeness: crate::audit::PayloadCompleteness::PartialV01,
                    at: now,
                };
                scope.emit_substrate(event);
                Ok(BindFlow::Success)
            })
            .await;

        match pipeline_result {
            Ok(BindFlow::Success) => Ok(BoundSubstrateProof {
                proof: self,
                _life: PhantomData,
            }),
            Ok(BindFlow::DeniedAtPipeline { stage, reason }) => {
                Err(BindError::DeniedAtPipeline { stage, reason })
            }
            Ok(BindFlow::OracleStale { oracle, query }) => {
                Err(BindError::OracleStale { oracle, query })
            }
            Err(bind_err) => Err(bind_err),
        }
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

    /// Re-derive a substrate borrow.
    ///
    /// Re-checks expiry against [`SubstrateScope::MAX_AGE`].
    /// Successful reborrow is silent. On miss, emits
    /// [`crate::audit::SubstrateAuditEvent::ScopeBound`] with
    /// `outcome: BindOutcomeRepr::Expired` (no dedicated
    /// SubstrateReborrowFailed variant exists; reuse the
    /// success-path variant with the appropriate non-Success
    /// outcome).
    pub async fn reborrow<'r>(
        &'r self,
        ctx: &AuthContext<'_>,
    ) -> Result<SubstrateProofRef<'r, S>, BindFailureReason> {
        if self.proof.issued_at.elapsed() <= S::MAX_AGE {
            return Ok(SubstrateProofRef { proof: &self.proof });
        }

        let trace_id = self.proof.trace_id;
        let now = std::time::SystemTime::now();

        // Substrate reborrow can only happen with a Service
        // requester (the original bind was Service-only). If the
        // reborrow ctx isn't Service, fall back to silent failure
        // — we can't construct a forensic-honest ScopeBound event.
        let service = match ctx.requester() {
            Requester::Service(svc) => svc.clone(),
            _ => return Err(BindFailureReason::Expired),
        };
        let scope_repr = crate::target::TargetRepresentation::structural_only(
            crate::target::StructuralRepresentation::Scope {
                kind: crate::target::ScopeKind::Shard,
            },
        );

        let audit_result: Result<(), BindError> = crate::audit::composite_audit(
            trace_id,
            ctx.audit(),
            async |scope| {
                let event = crate::audit::SubstrateAuditEvent::ScopeBound {
                    trace_id,
                    service,
                    scope_repr,
                    capability: S::KIND,
                    outcome: crate::authority::BindOutcomeRepr::Expired {
                        issued_at: self.proof.issued_at,
                        max_age: S::MAX_AGE,
                    },
                    payload_completeness: crate::audit::PayloadCompleteness::PartialV01,
                    at: now,
                };
                scope.emit_substrate(event);
                Ok::<(), BindError>(())
            },
        )
        .await;

        match audit_result {
            Ok(()) => Err(BindFailureReason::Expired),
            Err(_) => Err(BindFailureReason::AuditUnavailable),
        }
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

    /// Bind the moderation proof against a target.
    ///
    /// Consumes `self`. Pipeline (v0.1):
    /// - **Pre-checks** (no audit): target match, context match,
    ///   expiry.
    /// - **Stage 0 — DeprecationGate**: consults
    ///   [`crate::KRYPHOCRON_LEXICON_REGISTRY`] for the moderation
    ///   subject's NSID (via [`crate::HasResourceLocation`]).
    ///   Moderation operations on deprecated lexicons fail closed.
    /// - **Stage 5 — Audit emit**: emits the class-discriminating
    ///   variant via composite_audit:
    ///   [`crate::audit::ModerationAuditEvent::ModeratorInspected`]
    ///   for [`crate::authority::v1::ModeratorRead`],
    ///   [`crate::audit::ModerationAuditEvent::ModeratorTookDown`]
    ///   for [`crate::authority::v1::ModeratorTakedown`],
    ///   [`crate::audit::ModerationAuditEvent::ModeratorRestored`]
    ///   for [`crate::authority::v1::ModeratorRestore`]. Each carries
    ///   `outcome: BindOutcomeRepr::Success` (where applicable).
    /// - **Inspection-queue emit (post-composite-audit)**: after
    ///   the audit commits, fans an
    ///   [`crate::InspectionNotification`] to the resource owner's
    ///   queue via [`crate::ingress::AuditSinks::inspection_queue`].
    ///   **Outside composite-rollback semantics** per §6.7
    ///   ("notifications are diagnostic, not authoritative") — if
    ///   the audit commit succeeds but the inspection enqueue
    ///   fails, the audit stands.
    ///
    /// `rationale` is the moderator-declared rationale (§6.5
    /// round-1 patch F2 length-bounded). It surfaces in both the
    /// audit event and the inspection notification.
    ///
    /// # Errors
    ///
    /// Returns precondition errors without audit emit.
    /// [`BindError::DeniedAtPipeline`] for stage failures.
    /// [`BindError::AuditUnavailable`] / [`BindError::AuditPanicked`]
    /// on audit-machinery failure.
    pub async fn bind<'p>(
        self,
        ctx: &AuthContext<'_>,
        target: &<C as ModerationCapability>::Subject,
        rationale: crate::audit::ModeratorRationale,
    ) -> Result<BoundModerationProof<'p, C>, BindError>
    where
        Self: 'p,
        <C as ModerationCapability>::Subject:
            PartialEq + crate::authority::HasResourceLocation,
    {
        precheck_target_match(&self.subject, target)?;
        precheck_context_match(&self.requester, ctx)?;
        precheck_expired(self.issued_at, C::MAX_AGE)?;

        let trace_id = self.trace_id;
        let moderator_did = self.requester.clone();
        let now = std::time::SystemTime::now();
        let target_did = target.resource_did().clone();
        let target_nsid = target.resource_nsid().clone();
        let target_repr = crate::target::TargetRepresentation::structural_only(
            crate::target::StructuralRepresentation::Resource {
                did: target_did.clone(),
                nsid: target_nsid.clone(),
            },
        );

        // ModerationSubject is the only v1 ModerationCapability
        // Subject. To extract its `case: ModerationCaseId` field
        // generically we'd need another sealed trait
        // (HasModerationCase). v0.1 ships with a placeholder
        // ModerationCaseId per the same v0.2 enrichment as
        // channel/substrate's per-class data extraction.
        let case = crate::authority::ModerationCaseId::from_bytes([0u8; 16]);

        let kind = C::KIND;
        let rationale_for_audit = rationale.clone();
        let rationale_for_notification = rationale;
        let target_repr_for_notification = target_repr.clone();
        let moderator_for_audit = moderator_did.clone();

        let pipeline_result: Result<BindFlow, BindError> =
            crate::audit::composite_audit(trace_id, ctx.audit(), async |scope| {
                // Stage 0: deprecation gate. Moderation ops on a
                // deprecated lexicon fail closed (regardless of
                // moderation kind — read/takedown/restore).
                if let Err(reason) = crate::authority::check_stage_0_deprecation(
                    &target_nsid,
                    now_unix_seconds(),
                ) {
                    let event = crate::audit::ModerationAuditEvent::ModerationIssuanceDenied {
                        trace_id,
                        moderator: moderator_for_audit.clone(),
                        capability: kind,
                        reason: reason.clone(),
                        at: now,
                    };
                    scope.emit_moderation(event);
                    return Ok(BindFlow::DeniedAtPipeline {
                        stage: PipelineStage::DeprecationGate,
                        reason,
                    });
                }

                // Stage 5: emit class-discriminating success event.
                // The C: ModerationCapability trait bound restricts
                // KIND to ModeratorRead / ModeratorTakedown /
                // ModeratorRestore. The fourth arm is unreachable
                // by construction; if a future ModerationCapability
                // adds a new KIND variant it must also add a match
                // arm here (catch-all panic surfaces the gap).
                let event = match kind {
                    crate::authority::CapabilityKind::ModeratorRead => {
                        crate::audit::ModerationAuditEvent::ModeratorInspected {
                            trace_id,
                            moderator: moderator_for_audit,
                            case,
                            target_repr: target_repr.clone(),
                            rationale: rationale_for_audit,
                            payload_completeness:
                                crate::audit::PayloadCompleteness::PartialV01,
                            at: now,
                        }
                    }
                    crate::authority::CapabilityKind::ModeratorTakedown => {
                        crate::audit::ModerationAuditEvent::ModeratorTookDown {
                            trace_id,
                            moderator: moderator_for_audit,
                            case,
                            target_repr: target_repr.clone(),
                            outcome: crate::authority::BindOutcomeRepr::Success,
                            rationale: rationale_for_audit,
                            payload_completeness:
                                crate::audit::PayloadCompleteness::PartialV01,
                            at: now,
                        }
                    }
                    crate::authority::CapabilityKind::ModeratorRestore => {
                        crate::audit::ModerationAuditEvent::ModeratorRestored {
                            trace_id,
                            moderator: moderator_for_audit,
                            case,
                            target_repr: target_repr.clone(),
                            outcome: crate::authority::BindOutcomeRepr::Success,
                            rationale: rationale_for_audit,
                            payload_completeness:
                                crate::audit::PayloadCompleteness::PartialV01,
                            at: now,
                        }
                    }
                    other => unreachable!(
                        "non-moderation capability kind {other:?} reached ModerationProof::bind"
                    ),
                };
                scope.emit_moderation(event);
                Ok(BindFlow::Success)
            })
            .await;

        // Inspection-queue emit (post-composite-audit, OUTSIDE
        // composite-rollback semantics per §6.7). Only fires on a
        // successful bind — denial paths skip the notification.
        if matches!(pipeline_result, Ok(BindFlow::Success)) {
            let inspection_kind = match kind {
                crate::authority::CapabilityKind::ModeratorRead => {
                    crate::authority::InspectionKind::ModeratorRead {
                        case,
                        rationale: rationale_for_notification,
                    }
                }
                crate::authority::CapabilityKind::ModeratorTakedown => {
                    crate::authority::InspectionKind::Takedown {
                        case,
                        rationale: rationale_for_notification,
                    }
                }
                crate::authority::CapabilityKind::ModeratorRestore => {
                    crate::authority::InspectionKind::Restore {
                        case,
                        rationale: rationale_for_notification,
                    }
                }
                other => unreachable!(
                    "non-moderation capability kind {other:?} reached inspection-kind dispatch"
                ),
            };
            let mut notification_id_bytes = [0u8; 16];
            getrandom::getrandom(&mut notification_id_bytes)
                .expect("§6.7 notification-id init: OS CSPRNG unavailable");
            let notification = crate::authority::InspectionNotification {
                notification_id: crate::authority::NotificationId::from_bytes(
                    notification_id_bytes,
                ),
                trace_id,
                kind: inspection_kind,
                target_repr: target_repr_for_notification,
                at: now,
            };
            ctx.audit()
                .inspection_queue
                .enqueue(&target_did, notification);
        }

        match pipeline_result {
            Ok(BindFlow::Success) => Ok(BoundModerationProof {
                proof: self,
                _life: PhantomData,
            }),
            Ok(BindFlow::DeniedAtPipeline { stage, reason }) => {
                Err(BindError::DeniedAtPipeline { stage, reason })
            }
            Ok(BindFlow::OracleStale { oracle, query }) => {
                Err(BindError::OracleStale { oracle, query })
            }
            Err(bind_err) => Err(bind_err),
        }
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

    /// Re-derive a moderation borrow.
    ///
    /// Re-checks expiry against
    /// [`ModerationCapability::MAX_AGE`]. Successful reborrow is
    /// silent.
    ///
    /// **V0.1 audit gap**: on miss, returns
    /// [`BindFailureReason::Expired`] without an audit emit. v1's
    /// audit vocabulary has no ModerationReborrowFailed variant
    /// (unlike user/channel which have ReborrowFailed /
    /// ChannelReborrowFailed). v0.2 enrichment: introduce a
    /// dedicated variant or a generic reborrow-failed shape.
    pub async fn reborrow<'r>(
        &'r self,
        _ctx: &AuthContext<'_>,
    ) -> Result<ModerationProofRef<'r, C>, BindFailureReason> {
        if self.proof.issued_at.elapsed() <= C::MAX_AGE {
            return Ok(ModerationProofRef { proof: &self.proof });
        }
        Err(BindFailureReason::Expired)
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
    // bind/reborrow shared-helper tests.
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
        let correlation_key =
            crate::identity::CorrelationKey::from_bytes([0u8; 32]);

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
                correlation_key: &correlation_key,
            },
            OracleSet {
                block: &*oracle,
                audience: &*oracle,
                mute: &*oracle,
            },
            AttributionChain::empty(),
            crate::authority::capability::CapabilitySet::empty(),
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
                correlation_key: &correlation_key,
            },
            OracleSet {
                block: &*oracle,
                audience: &*oracle,
                mute: &*oracle,
            },
            AttributionChain::empty(),
            crate::authority::capability::CapabilitySet::empty(),
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

    /// `From<CompositeAuditError> for BindError` maps audit-
    /// machinery failures to AuditUnavailable, with
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
// bind/reborrow test infrastructure + tests.
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

    // ---- Configurable audience oracle ----
    //
    // Mirrors `ConfigurableBlockOracle`: the returned `state`,
    // `synced_at`, and `freshness_bound` are all tunable so tests can
    // drive the §4.3 stage-3 InAudience / NotInAudience /
    // NoAudienceConfigured / stale paths. The default
    // (`fresh_in_audience`) affirms membership with a just-now sync,
    // which is the success-path oracle for private binds.
    pub struct ConfigurableAudienceOracle {
        pub state: AudienceState,
        pub synced_at: SystemTime,
        pub freshness_bound: Duration,
    }
    impl ConfigurableAudienceOracle {
        pub fn fresh_in_audience() -> Self {
            ConfigurableAudienceOracle {
                state: AudienceState::InAudience,
                synced_at: SystemTime::now(),
                freshness_bound: Duration::from_secs(60),
            }
        }
        pub fn fresh_with_state(state: AudienceState) -> Self {
            ConfigurableAudienceOracle {
                state,
                synced_at: SystemTime::now(),
                freshness_bound: Duration::from_secs(60),
            }
        }
    }
    impl AudienceOracle for ConfigurableAudienceOracle {
        fn audience_state(
            &self,
            _: &Did,
            _: &crate::authority::ResourceId,
        ) -> AudienceState {
            self.state
        }
        fn last_synced_at(&self) -> SystemTime {
            self.synced_at
        }
        fn data_freshness_bound(&self) -> Duration {
            self.freshness_bound
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
        pub correlation_key: crate::identity::CorrelationKey,
        pub block: Arc<ConfigurableBlockOracle>,
        pub audience: Arc<ConfigurableAudienceOracle>,
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
                correlation_key: crate::identity::CorrelationKey::from_bytes([0u8; 32]),
                block: Arc::new(ConfigurableBlockOracle {
                    state: BlockState::None,
                }),
                audience: Arc::new(ConfigurableAudienceOracle::fresh_in_audience()),
                mute: Arc::new(NoopMuteOracle),
            }
        }

        pub fn with_block_state(state: BlockState) -> Self {
            let mut f = Self::new();
            f.block = Arc::new(ConfigurableBlockOracle { state });
            f
        }

        pub fn with_audience(audience: ConfigurableAudienceOracle) -> Self {
            let mut f = Self::new();
            f.audience = Arc::new(audience);
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
                    correlation_key: &self.correlation_key,
                },
                OracleSet {
                    block: &*self.block,
                    audience: &*self.audience,
                    mute: &*self.mute,
                },
                AttributionChain::empty(),
                crate::authority::capability::CapabilitySet::empty(),
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
// UserProof::bind + BoundUserProof::reborrow tests.
// ========================================================

#[cfg(test)]
mod user_bind_tests {
    use super::bind_test_fixtures::*;
    use super::*;
    use crate::audit::UserAuditEvent;
    use crate::authority::v1::{ParticipatePrivate, ViewPrivate};
    use crate::authority::{issue_user, BindOutcomeRepr, CapabilityClass, CapabilityKind};
    use crate::oracle::{
        AudienceOracleQuery, AudienceState, BlockOracleQuery, BlockState, OracleKind,
        OracleQueryKind,
    };
    use std::time::{Duration, SystemTime};

    /// Helper: issue a UserProof<ViewPrivate> via the §4.3
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

    /// §4.3 stage 3 — AudienceConsultation: a requester the audience
    /// oracle reports as `NotInAudience` is denied inline at stage 3
    /// (§11), so the denial surfaces at `AudienceConsultation` with a
    /// `NotInAudience` reason — mirroring the stage-2 block deny.
    /// Before the stage-3 wiring the audience field stayed at its
    /// fail-open default and this bind would have succeeded without
    /// ever consulting membership.
    #[tokio::test]
    async fn bind_denied_when_requester_not_in_audience() {
        let fixture =
            BindFixture::with_audience(ConfigurableAudienceOracle::fresh_with_state(
                AudienceState::NotInAudience,
            ));
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        let r = proof.bind(&ctx, &sample_resource_id()).await;
        let Err(err) = r else {
            panic!("expected Err (NotInAudience), got Ok");
        };
        match err {
            BindError::DeniedAtPipeline { stage, reason } => {
                assert_eq!(stage, PipelineStage::AudienceConsultation);
                match reason {
                    DenialReason::NotInAudience { query, state } => {
                        assert_eq!(
                            query,
                            AudienceOracleQuery::RequesterAgainstResourceAudience
                        );
                        assert!(matches!(state, AudienceState::NotInAudience));
                    }
                    other => panic!("expected NotInAudience, got {other:?}"),
                }
            }
            other => panic!("expected DeniedAtPipeline(AudienceConsultation), got {other:?}"),
        }

        let captured = fixture.user.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            UserAuditEvent::CapabilityIssuanceDenied { reason, .. } => {
                assert!(matches!(reason, DenialReason::NotInAudience { .. }));
            }
            other => panic!("expected CapabilityIssuanceDenied, got {other:?}"),
        }
    }

    /// §4.5 Decision B: `NoAudienceConfigured` denies the private
    /// capability just like `NotInAudience` — a resource with no
    /// configured audience grants no private read. Denied inline at
    /// stage 3, so it surfaces at `AudienceConsultation` with a
    /// `NotInAudience` reason carrying the `NoAudienceConfigured`
    /// state.
    #[tokio::test]
    async fn bind_denied_when_no_audience_configured() {
        let fixture =
            BindFixture::with_audience(ConfigurableAudienceOracle::fresh_with_state(
                AudienceState::NoAudienceConfigured,
            ));
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        let r = proof.bind(&ctx, &sample_resource_id()).await;
        let Err(err) = r else {
            panic!("expected Err (NoAudienceConfigured), got Ok");
        };
        match err {
            BindError::DeniedAtPipeline {
                stage: PipelineStage::AudienceConsultation,
                reason: DenialReason::NotInAudience { state, .. },
            } => {
                assert!(matches!(state, AudienceState::NoAudienceConfigured));
            }
            other => {
                panic!("expected DeniedAtPipeline(AudienceConsultation, NotInAudience), got {other:?}")
            }
        }
        assert_eq!(fixture.user.captured().len(), 1);
    }

    /// §4.3 stage 3 / §4.6: an audience oracle whose `last_synced_at`
    /// is older than its `data_freshness_bound` fails the bind closed
    /// with `OracleStale` rather than serving possibly-revoked
    /// membership. The stale outcome has no `DenialReason`, so it is
    /// recorded as `CapabilityBound { outcome: OracleStale }` (a
    /// non-success bind outcome), and the caller sees
    /// `BindError::OracleStale`.
    #[tokio::test]
    async fn bind_fails_closed_when_audience_oracle_stale() {
        // InAudience would otherwise grant, but the ancient sync makes
        // the oracle stale before the membership answer is trusted.
        let fixture = BindFixture::with_audience(ConfigurableAudienceOracle {
            state: AudienceState::InAudience,
            synced_at: SystemTime::UNIX_EPOCH,
            freshness_bound: Duration::from_secs(60),
        });
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_view_private_for(&ctx, sample_resource_id());

        let r = proof.bind(&ctx, &sample_resource_id()).await;
        let Err(err) = r else {
            panic!("expected Err (OracleStale), got Ok");
        };
        match err {
            BindError::OracleStale { oracle, query } => {
                assert_eq!(oracle, OracleKind::Audience);
                assert_eq!(
                    query,
                    OracleQueryKind::Audience(
                        AudienceOracleQuery::RequesterAgainstResourceAudience
                    )
                );
            }
            other => panic!("expected OracleStale, got {other:?}"),
        }

        let captured = fixture.user.captured();
        assert_eq!(captured.len(), 1, "stale bind emits one CapabilityBound");
        match &captured[0] {
            UserAuditEvent::CapabilityBound { outcome, .. } => match outcome {
                BindOutcomeRepr::OracleStale {
                    oracle,
                    query,
                    sync_age,
                } => {
                    assert_eq!(*oracle, OracleKind::Audience);
                    assert_eq!(
                        *query,
                        OracleQueryKind::Audience(
                            AudienceOracleQuery::RequesterAgainstResourceAudience
                        )
                    );
                    assert!(*sync_age > Duration::from_secs(60));
                }
                other => panic!("expected OracleStale outcome, got {other:?}"),
            },
            other => panic!("expected CapabilityBound, got {other:?}"),
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

// ========================================================
// ChannelProof::bind + BoundChannelProof::reborrow tests.
// ========================================================

#[cfg(test)]
mod channel_bind_tests {
    use super::bind_test_fixtures::*;
    use super::*;
    use crate::audit::ChannelAuditEvent;
    use crate::authority::v1::EmitToSyncChannel;
    use crate::authority::{issue_channel, BindOutcomeRepr, CapabilityClass, CapabilityKind};
    use std::time::Duration;

    fn sample_channel_subject() -> crate::authority::ChannelBinding {
        crate::authority::ChannelBinding {
            peer: crate::identity::ServiceIdentity::new_internal(
                sample_did(),
                crate::identity::KeyId::from_bytes([0u8; 32]),
                crate::identity::PublicKey {
                    algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                    bytes: [0u8; 32],
                },
                None,
            ),
            session_id: crate::identity::SessionId::from_bytes([0u8; 32]),
        }
    }

    fn issue_emit_for(
        ctx: &AuthContext<'_>,
        subject: crate::authority::ChannelBinding,
    ) -> ChannelProof<EmitToSyncChannel> {
        match issue_channel::<EmitToSyncChannel>(ctx, subject) {
            Ok(p) => p,
            Err(_) => panic!("issuance prerequisite failed"),
        }
    }

    /// §4.3 happy path: channel bind with Did requester returns
    /// Ok(BoundChannelProof). One ChannelBound event captured
    /// with outcome Success.
    #[tokio::test]
    async fn bind_succeeds_with_did_requester() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_emit_for(&ctx, sample_channel_subject());

        let r = proof.bind(&ctx, &sample_channel_subject()).await;
        assert!(r.is_ok());

        let captured = fixture.channel.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            ChannelAuditEvent::ChannelBound {
                endpoint, outcome, ..
            } => {
                assert_eq!(*endpoint, CapabilityKind::EmitToSyncChannel);
                assert!(matches!(outcome, BindOutcomeRepr::Success));
            }
            other => panic!("expected ChannelBound, got {other:?}"),
        }
    }

    /// §4.3 precondition: target ≠ proof.subject → TargetMismatch
    /// (no audit emit).
    #[tokio::test]
    async fn bind_rejects_target_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_emit_for(&ctx, sample_channel_subject());

        // Different SessionId than what the proof was issued for
        let different_target = crate::authority::ChannelBinding {
            peer: crate::identity::ServiceIdentity::new_internal(
                sample_did(),
                crate::identity::KeyId::from_bytes([0u8; 32]),
                crate::identity::PublicKey {
                    algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                    bytes: [0u8; 32],
                },
                None,
            ),
            session_id: crate::identity::SessionId::from_bytes([0xFF; 32]),
        };
        let r = proof.bind(&ctx, &different_target).await;
        assert!(matches!(r, Err(BindError::TargetMismatch)));
        assert_eq!(fixture.channel.captured().len(), 0);
    }

    /// §4.3 precondition: AuthContext requester ≠ proof.requester
    /// → ContextMismatch (no audit emit).
    #[tokio::test]
    async fn bind_rejects_context_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let ctx_a = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_emit_for(&ctx_a, sample_channel_subject());

        let ctx_b = fixture.build_ctx(Requester::Did(sample_did_other()));
        let r = proof.bind(&ctx_b, &sample_channel_subject()).await;
        assert!(matches!(r, Err(BindError::ContextMismatch)));
        assert_eq!(fixture.channel.captured().len(), 0);
    }

    /// §4.3 reborrow: channel bound proof inside MAX_AGE re-derives
    /// silent ProofRef. No audit emit on success.
    #[tokio::test]
    async fn reborrow_succeeds_within_max_age() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let proof = issue_emit_for(&ctx, sample_channel_subject());

        let bound = match proof.bind(&ctx, &sample_channel_subject()).await {
            Ok(b) => b,
            Err(_) => panic!("bind prerequisite failed"),
        };
        let captured_after_bind = fixture.channel.captured().len();

        let r = bound.reborrow(&ctx).await;
        assert!(r.is_ok());
        assert_eq!(
            fixture.channel.captured().len(),
            captured_after_bind,
            "successful reborrow is silent"
        );
    }

    /// §4.3 reborrow: past MAX_AGE returns Expired and emits
    /// ChannelReborrowFailed.
    #[tokio::test]
    async fn reborrow_returns_expired_past_max_age_and_emits_event() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));

        // EmitToSyncChannel MAX_AGE = 60s; backdate 100s.
        let backdated = ChannelProof::<EmitToSyncChannel>::new_internal(
            sample_did(),
            sample_channel_subject(),
            Instant::now() - Duration::from_secs(100),
            AuthorityId::from_bytes([0u8; 16]),
            TraceId::from_bytes([0xCD; 16]),
        );
        let bound = BoundChannelProof {
            proof: backdated,
            _life: PhantomData,
        };

        let r = bound.reborrow(&ctx).await;
        assert!(matches!(r, Err(BindFailureReason::Expired)));

        let captured = fixture.channel.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            ChannelAuditEvent::ChannelReborrowFailed { reason, .. } => {
                assert!(matches!(reason, BindFailureReason::Expired));
            }
            other => panic!("expected ChannelReborrowFailed, got {other:?}"),
        }
    }

    #[test]
    fn channel_class_discriminator_pinned() {
        assert_eq!(
            CapabilityKind::EmitToSyncChannel.class(),
            CapabilityClass::Channel
        );
    }
}

// ========================================================
// SubstrateProof::bind + BoundSubstrateProof::reborrow tests.
// ========================================================

#[cfg(test)]
mod substrate_bind_tests {
    use super::bind_test_fixtures::*;
    use super::*;
    use crate::audit::SubstrateAuditEvent;
    use crate::authority::v1::ScanShard;
    use crate::authority::{
        issue_substrate, BindOutcomeRepr, CapabilityClass, CapabilityKind,
    };
    use std::time::Duration;

    fn sample_substrate_subject() -> crate::authority::ScopeSelector {
        crate::authority::ScopeSelector::Shard(
            crate::authority::ShardRange::new(
                crate::authority::ShardId::from_bytes([0; 8]),
                crate::authority::ShardId::from_bytes([0xFF; 8]),
            )
            .unwrap(),
        )
    }

    fn sample_service_identity() -> crate::identity::ServiceIdentity {
        crate::identity::ServiceIdentity::new_internal(
            sample_did(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn issue_scan_for(
        ctx: &AuthContext<'_>,
        subject: crate::authority::ScopeSelector,
    ) -> SubstrateProof<ScanShard> {
        match issue_substrate::<ScanShard>(ctx, subject) {
            Ok(p) => p,
            Err(_) => panic!("issuance prerequisite failed"),
        }
    }

    /// §4.3 / §4.6 happy path: substrate bind with Service
    /// requester returns Ok(BoundSubstrateProof). One ScopeBound
    /// event captured with outcome Success.
    #[tokio::test]
    async fn bind_succeeds_with_service_requester() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_scan_for(&ctx, sample_substrate_subject());

        let r = proof.bind(&ctx, &sample_substrate_subject()).await;
        assert!(r.is_ok());

        let captured = fixture.substrate.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            SubstrateAuditEvent::ScopeBound {
                capability, outcome, ..
            } => {
                assert_eq!(*capability, CapabilityKind::ScanShard);
                assert!(matches!(outcome, BindOutcomeRepr::Success));
            }
            other => panic!("expected ScopeBound, got {other:?}"),
        }
    }

    /// §4.3 precondition: target ≠ proof.subject → TargetMismatch.
    #[tokio::test]
    async fn bind_rejects_target_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_scan_for(&ctx, sample_substrate_subject());

        let different_target = crate::authority::ScopeSelector::Shard(
            crate::authority::ShardRange::new(
                crate::authority::ShardId::from_bytes([0x10; 8]),
                crate::authority::ShardId::from_bytes([0x20; 8]),
            )
            .unwrap(),
        );
        let r = proof.bind(&ctx, &different_target).await;
        assert!(matches!(r, Err(BindError::TargetMismatch)));
        assert_eq!(fixture.substrate.captured().len(), 0);
    }

    /// §4.3 precondition: AuthContext requester ≠ proof.requester
    /// → ContextMismatch.
    #[tokio::test]
    async fn bind_rejects_context_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let svc_a = sample_service_identity();
        let ctx_a = fixture.build_ctx(Requester::Service(svc_a));
        let proof = issue_scan_for(&ctx_a, sample_substrate_subject());

        let svc_b = crate::identity::ServiceIdentity::new_internal(
            sample_did_other(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        );
        let ctx_b = fixture.build_ctx(Requester::Service(svc_b));
        let r = proof.bind(&ctx_b, &sample_substrate_subject()).await;
        assert!(matches!(r, Err(BindError::ContextMismatch)));
        assert_eq!(fixture.substrate.captured().len(), 0);
    }

    /// §4.3 reborrow: substrate bound proof inside MAX_AGE
    /// re-derives silent ProofRef.
    #[tokio::test]
    async fn reborrow_succeeds_within_max_age() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_scan_for(&ctx, sample_substrate_subject());

        let bound = match proof.bind(&ctx, &sample_substrate_subject()).await {
            Ok(b) => b,
            Err(_) => panic!("bind prerequisite failed"),
        };
        let captured_after_bind = fixture.substrate.captured().len();

        let r = bound.reborrow(&ctx).await;
        assert!(r.is_ok());
        assert_eq!(
            fixture.substrate.captured().len(),
            captured_after_bind,
            "successful reborrow is silent"
        );
    }

    /// §4.3 reborrow: past MAX_AGE returns Expired and emits
    /// ScopeBound{outcome: Expired} (substrate reuses the
    /// success-path variant with non-Success outcome — no
    /// dedicated SubstrateReborrowFailed variant exists).
    #[tokio::test]
    async fn reborrow_returns_expired_past_max_age_and_emits_event() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));

        // ScanShard MAX_AGE = 120s; backdate 200s.
        let backdated = SubstrateProof::<ScanShard>::new_internal(
            sample_did(),
            sample_substrate_subject(),
            Instant::now() - Duration::from_secs(200),
            AuthorityId::from_bytes([0u8; 16]),
            TraceId::from_bytes([0xCD; 16]),
        );
        let bound = BoundSubstrateProof {
            proof: backdated,
            _life: PhantomData,
        };

        let r = bound.reborrow(&ctx).await;
        assert!(matches!(r, Err(BindFailureReason::Expired)));

        let captured = fixture.substrate.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            SubstrateAuditEvent::ScopeBound { outcome, .. } => {
                assert!(
                    matches!(outcome, BindOutcomeRepr::Expired { .. }),
                    "expected outcome=Expired, got {outcome:?}"
                );
            }
            other => panic!("expected ScopeBound{{outcome: Expired}}, got {other:?}"),
        }
    }

    #[test]
    fn substrate_class_discriminator_pinned() {
        assert_eq!(
            CapabilityKind::ScanShard.class(),
            CapabilityClass::Substrate
        );
    }
}

// ========================================================
// ModerationProof::bind + BoundModerationProof::reborrow tests.
// ========================================================

#[cfg(test)]
mod moderation_bind_tests {
    use super::bind_test_fixtures::*;
    use super::*;
    use crate::audit::{ModerationAuditEvent, ModeratorRationale};
    use crate::authority::v1::{ModeratorRead, ModeratorTakedown};
    use crate::authority::{
        issue_moderation, BindOutcomeRepr, CapabilityClass, CapabilityKind, InspectionKind,
    };
    use std::time::Duration;

    fn sample_moderation_subject() -> crate::authority::ModerationSubject {
        crate::authority::ModerationSubject {
            resource: sample_resource_id(),
            case: crate::authority::ModerationCaseId::from_bytes([0u8; 16]),
        }
    }

    fn sample_service_identity() -> crate::identity::ServiceIdentity {
        crate::identity::ServiceIdentity::new_internal(
            sample_did(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn sample_rationale() -> ModeratorRationale {
        ModeratorRationale::Declared(
            crate::audit::BoundedString::<{ crate::audit::MAX_RATIONALE_LEN }>::new(
                "v0.1 test rationale",
            )
            .unwrap(),
        )
    }

    fn issue_modread_for(
        ctx: &AuthContext<'_>,
        subject: crate::authority::ModerationSubject,
    ) -> ModerationProof<ModeratorRead> {
        match issue_moderation::<ModeratorRead>(ctx, subject) {
            Ok(p) => p,
            Err(_) => panic!("issuance prerequisite failed"),
        }
    }

    /// §4.3 + §6.7 happy path: ModeratorRead bind with Service
    /// requester returns Ok(BoundModerationProof). One
    /// ModeratorInspected event captured AND one inspection
    /// notification enqueued (dual-emit per §6.7).
    #[tokio::test]
    async fn bind_moderator_read_succeeds_and_dual_emits() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_modread_for(&ctx, sample_moderation_subject());

        let r = proof
            .bind(&ctx, &sample_moderation_subject(), sample_rationale())
            .await;
        assert!(r.is_ok());

        // Audit emission
        let captured_audit = fixture.moderation.captured();
        assert_eq!(captured_audit.len(), 1);
        match &captured_audit[0] {
            ModerationAuditEvent::ModeratorInspected { rationale, .. } => {
                assert!(matches!(rationale, ModeratorRationale::Declared(_)));
            }
            other => panic!("expected ModeratorInspected, got {other:?}"),
        }

        // Inspection-queue emission (separate channel per §6.7)
        let captured_notifications = fixture.inspection.captured();
        assert_eq!(
            captured_notifications.len(),
            1,
            "ModeratorRead bind enqueues one InspectionNotification"
        );
        let (_owner, notification) = &captured_notifications[0];
        match &notification.kind {
            InspectionKind::ModeratorRead { rationale, .. } => {
                assert!(matches!(rationale, ModeratorRationale::Declared(_)));
            }
            other => panic!("expected InspectionKind::ModeratorRead, got {other:?}"),
        }
        // The trace_id is shared between the audit event and the
        // inspection notification (§6.7 correlation discipline).
        assert_eq!(
            notification.trace_id,
            match &captured_audit[0] {
                ModerationAuditEvent::ModeratorInspected { trace_id, .. } => *trace_id,
                _ => panic!("unreachable"),
            },
            "audit event and inspection notification share trace_id"
        );
    }

    /// §6.5: ModeratorTakedown bind emits the ModeratorTookDown
    /// variant (not ModeratorInspected) — the kind dispatch maps
    /// to the right audit shape.
    #[tokio::test]
    async fn bind_moderator_takedown_emits_took_down_variant() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = match issue_moderation::<ModeratorTakedown>(&ctx, sample_moderation_subject()) {
            Ok(p) => p,
            Err(_) => panic!("issuance prerequisite failed"),
        };

        let r = proof
            .bind(&ctx, &sample_moderation_subject(), sample_rationale())
            .await;
        assert!(r.is_ok());

        let captured = fixture.moderation.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            ModerationAuditEvent::ModeratorTookDown { outcome, .. } => {
                assert!(matches!(outcome, BindOutcomeRepr::Success));
            }
            other => panic!("expected ModeratorTookDown, got {other:?}"),
        }

        // Inspection notification: Takedown variant
        let captured_notifications = fixture.inspection.captured();
        assert_eq!(captured_notifications.len(), 1);
        match &captured_notifications[0].1.kind {
            InspectionKind::Takedown { .. } => {}
            other => panic!("expected InspectionKind::Takedown, got {other:?}"),
        }
    }

    /// §4.3 precondition: target ≠ proof.subject → TargetMismatch
    /// (no audit emit, no inspection emit).
    #[tokio::test]
    async fn bind_rejects_target_mismatch_at_precondition() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_modread_for(&ctx, sample_moderation_subject());

        let different_target = crate::authority::ModerationSubject {
            resource: sample_resource_id(),
            case: crate::authority::ModerationCaseId::from_bytes([0xFF; 16]),
        };
        let r = proof
            .bind(&ctx, &different_target, sample_rationale())
            .await;
        assert!(matches!(r, Err(BindError::TargetMismatch)));
        assert_eq!(fixture.moderation.captured().len(), 0);
        assert_eq!(
            fixture.inspection.captured().len(),
            0,
            "precondition failure emits NEITHER audit NOR inspection"
        );
    }

    /// §6.7: denial paths skip the inspection-queue emit (only
    /// successful binds notify the resource owner).
    #[tokio::test]
    async fn denial_path_skips_inspection_emit() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_modread_for(&ctx, sample_moderation_subject());

        // Force denial via context mismatch
        let svc_b = crate::identity::ServiceIdentity::new_internal(
            sample_did_other(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        );
        let ctx_b = fixture.build_ctx(Requester::Service(svc_b));
        let r = proof
            .bind(&ctx_b, &sample_moderation_subject(), sample_rationale())
            .await;
        assert!(matches!(r, Err(BindError::ContextMismatch)));
        // Both audit and inspection are silent on precondition
        // failure (and on stage-0 denial, though we can't trigger
        // that with v1's all-Active registry).
        assert_eq!(fixture.moderation.captured().len(), 0);
        assert_eq!(fixture.inspection.captured().len(), 0);
    }

    /// §4.3 reborrow: moderation bound proof inside MAX_AGE
    /// re-derives silent ProofRef.
    #[tokio::test]
    async fn reborrow_succeeds_within_max_age() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let proof = issue_modread_for(&ctx, sample_moderation_subject());

        let bound = match proof
            .bind(&ctx, &sample_moderation_subject(), sample_rationale())
            .await
        {
            Ok(b) => b,
            Err(_) => panic!("bind prerequisite failed"),
        };
        let captured_after_bind = fixture.moderation.captured().len();

        let r = bound.reborrow(&ctx).await;
        assert!(r.is_ok());
        assert_eq!(
            fixture.moderation.captured().len(),
            captured_after_bind,
            "successful reborrow is silent"
        );
    }

    /// §4.3 reborrow: past MAX_AGE returns Expired. v1's audit
    /// vocabulary has no ModerationReborrowFailed variant — the
    /// failure is silent at the audit layer (v0.2 enrichment).
    #[tokio::test]
    async fn reborrow_returns_expired_past_max_age_silently() {
        let fixture = BindFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));

        // ModeratorRead MAX_AGE = 30s; backdate 60s.
        let backdated = ModerationProof::<ModeratorRead>::new_internal(
            sample_did(),
            sample_moderation_subject(),
            Instant::now() - Duration::from_secs(60),
            AuthorityId::from_bytes([0u8; 16]),
            TraceId::from_bytes([0xCD; 16]),
        );
        let bound = BoundModerationProof {
            proof: backdated,
            _life: PhantomData,
        };

        let r = bound.reborrow(&ctx).await;
        assert!(matches!(r, Err(BindFailureReason::Expired)));
        assert_eq!(
            fixture.moderation.captured().len(),
            0,
            "moderation reborrow miss is silent at the audit layer (v0.2 enrichment for emit)"
        );
    }

    #[test]
    fn moderation_class_discriminator_pinned() {
        assert_eq!(
            CapabilityKind::ModeratorRead.class(),
            CapabilityClass::Moderation
        );
    }
}

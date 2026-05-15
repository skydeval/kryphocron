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
    /// per §4.3 / §4.9 A1 invariant. On success returns
    /// `BoundUserProof`; on any non-success outcome the audit
    /// emit fires first and `Err(BindError)` is returned.
    ///
    /// **Phase 1 stub.** Phase 4 wires `compute_bind_outcome`
    /// against the §4.3 pipeline.
    pub fn bind<'p>(
        self,
        _ctx: &AuthContext<'_>,
        _target: &<C as UserCapability>::Subject,
    ) -> Result<BoundUserProof<'p, C>, BindError>
    where
        Self: 'p,
    {
        unimplemented!(
            "§4.3 UserProof::bind: Phase 4 wires the pipeline + audit emit"
        );
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
    /// Re-checks expiry against
    /// `min(C::MAX_AGE, deployment_config.max_age_for::<C>())`.
    /// Success is silent. Failure emits a `ReborrowFailed` audit
    /// event and returns an error.
    ///
    /// Phase 1 stub.
    pub fn reborrow<'r>(
        &'r self,
        _ctx: &AuthContext<'_>,
    ) -> Result<UserProofRef<'r, C>, BindFailureReason> {
        unimplemented!("§4.3 BoundUserProof::reborrow: Phase 4 wires re-check + audit emit");
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

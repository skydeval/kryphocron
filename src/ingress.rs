// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.2 ingress submodule and the [`AuthContext`] type.
//!
//! [`AuthContext`] is the in-process authentication context the
//! substrate carries through every authorization decision. It is
//! constructed only via the `ingress` submodule functions
//! (`from_xrpc_request`, `from_service_request`,
//! `from_sync_channel_message`, `anonymous_for_public_read`),
//! each of which accepts a verified-evidence type. Code outside
//! the crate cannot construct an [`AuthContext`] via
//! struct-literal syntax because every field is private and the
//! type carries a `PhantomData<*const ()>` to forbid `Clone`.
//!
//! Sub-context derivation uses [`AuthContext::derive_for`] over a
//! sealed [`Narrowing`] trait — only three [`Narrowing`] impls
//! ship, capturing the three legal transitions: drop-to-anonymous,
//! capability narrowing, and service-to-service delegation.

use core::marker::PhantomData;
use std::time::SystemTime;

use smallvec::SmallVec;
use thiserror::Error;

use crate::authority::capability::CapabilitySet;
use crate::authority::moderation::InspectionNotificationQueueImpl;
use crate::audit::{
    ChannelAuditSink, FallbackAuditSink, ModerationAuditSink, SubstrateAuditSink,
    UserAuditSink,
};
use crate::identity::{CorrelationKey, ServiceIdentity, TraceId};
use crate::oracle::{AudienceOracle, BlockOracle, MuteOracle};
use crate::proto::Did;
use crate::sealed;

/// Maximum depth of an [`AttributionChain`] (§4.2). Mirrors
/// [`crate::wire::AttributionChainWire`]'s `entries` cap.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// In-process authentication context (§4.2).
///
/// Carries the resolved requester identity, the forensic trace
/// id, references to the configured audit sinks and oracle set,
/// and the [`AttributionChain`] reconstructed from upstream
/// delegation (§4.8).
///
/// **Not `Clone`.** The `_no_clone` marker `PhantomData<*const ()>`
/// makes the auto-trait analysis exclude `Clone`. Operators that
/// need to flow context through async boundaries pass references
/// or rebuild via [`AuthContext::derive_for`].
pub struct AuthContext<'a> {
    requester: Requester,
    trace_id: TraceId,
    audit: AuditSinks<'a>,
    oracles: OracleSet<'a>,
    attribution_chain: AttributionChain,
    /// Capability set the context is authorized to carry
    /// (§4.2 / §4.8). For `Requester::Did` constructed from a
    /// verified JWT this is empty in v0.1 — the JWT scope is not
    /// projected into the AuthContext at the ingress layer; see
    /// [`from_xrpc_request`]'s doc. For `Requester::Service`
    /// constructed from a verified capability claim or sync
    /// message, it carries the claim's authorized capabilities.
    /// For `Requester::Anonymous` it is empty.
    ///
    /// Consumed by [`AuthContext::derive_for`]'s
    /// `NarrowCapabilities` path: the dropped set must be a
    /// subset of this field, otherwise the derivation fails
    /// with [`DeriveError::NarrowingExceedsAuthority`].
    capabilities: CapabilitySet,
    _no_clone: PhantomData<*const ()>,
}

// The *const () marker makes AuthContext !Send + !Sync by
// default, which is the substrate's discipline: AuthContext is
// process-local and used inside a single bind path. Manual Send +
// Sync impls are NOT shipped — operators that need to flow context
// across async boundaries pass references or rebuild via
// derive_for.

impl<'a> AuthContext<'a> {
    /// Crate-internal constructor. Reserved for the
    /// [`crate::ingress`] entry-point functions
    /// (`from_xrpc_request`, `from_service_request`,
    /// `from_sync_channel_message`, `anonymous_for_public_read`)
    /// that turn a verified-evidence type into an [`AuthContext`].
    #[must_use]
    pub(crate) fn new_internal(
        requester: Requester,
        trace_id: TraceId,
        audit: AuditSinks<'a>,
        oracles: OracleSet<'a>,
        attribution_chain: AttributionChain,
        capabilities: CapabilitySet,
    ) -> Self {
        AuthContext {
            requester,
            trace_id,
            audit,
            oracles,
            attribution_chain,
            capabilities,
            _no_clone: PhantomData,
        }
    }

    /// Borrow the capability set the context is authorized to
    /// carry (§4.2 / §4.8).
    ///
    /// See the [field documentation][Self#fields] for the
    /// per-requester semantics. v0.1 polish pass 2 adds this
    /// accessor alongside the structural superset check in
    /// [`Self::derive_for`]'s `NarrowCapabilities` path.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    /// Borrow the requester identity.
    #[must_use]
    pub fn requester(&self) -> &Requester {
        &self.requester
    }

    /// Return the forensic trace id.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Borrow the attribution chain reconstructed from upstream
    /// delegation (§4.8 W11).
    #[must_use]
    pub fn attribution_chain(&self) -> &AttributionChain {
        &self.attribution_chain
    }

    /// Borrow the audit-sink set.
    #[must_use]
    pub fn audit(&self) -> &AuditSinks<'a> {
        &self.audit
    }

    /// Borrow the oracle set.
    #[must_use]
    pub fn oracles(&self) -> &OracleSet<'a> {
        &self.oracles
    }

    /// Derive a narrowed sub-context (§4.2).
    ///
    /// Three legal transitions, expressed as the three [`Narrowing`]
    /// impl types: [`ToAnonymous`], [`NarrowCapabilities`], and
    /// [`ServiceToService`]. Sub-contexts inherit [`TraceId`] and
    /// extend [`AttributionChain`].
    ///
    /// Emits [`crate::audit::UserAuditEvent::DerivedContext`] on
    /// every derivation attempt (success and failure) per §4.2's
    /// "audit reflects action, not intent" discipline. The audit
    /// emit is **fire-and-forget**: if the user-class sink rejects
    /// the event, derive_for still returns its result (the
    /// forensic trail is degraded but the runtime correctness
    /// isn't compromised). Operators relying on derivation audit
    /// for compliance install reliable sinks. The emit is **NOT**
    /// routed through [`crate::audit::composite_audit`] — derivation
    /// is single-event single-sink.
    ///
    /// The `+ 'static` bound on `N` enables internal dispatch via
    /// [`std::any::Any`] downcast. v1's three [`Narrowing`] impls
    /// (all owned data, no references) already satisfy this; the
    /// bound is structurally non-breaking.
    ///
    /// # Errors
    ///
    /// See [`DeriveError`]. Failure paths emit a matching
    /// [`crate::audit::DerivationOutcome`] variant before
    /// returning.
    pub fn derive_for<N: Narrowing + 'static>(
        &self,
        narrowing: N,
    ) -> Result<AuthContext<'_>, DeriveError> {
        let now = SystemTime::now();
        let narrowing_any = &narrowing as &dyn std::any::Any;

        // Dispatch on the narrowing variant. Narrowing is sealed
        // (only the three crate-ship impls exist); the unreachable
        // arm covers a future v0.X variant addition that forgets
        // to extend this match.
        let (new_requester, derivation_reason, narrowing_kind, new_capabilities) =
            if narrowing_any.is::<ToAnonymous>() {
                // Anonymous carries no capabilities.
                (
                    Requester::Anonymous,
                    DerivationReason::DropPrivilegeToAnonymous,
                    crate::audit::NarrowingKind::ToAnonymous,
                    CapabilitySet::empty(),
                )
            } else if let Some(narrow) = narrowing_any.downcast_ref::<NarrowCapabilities>() {
                // v0.1 polish pass 2 wires the structural superset
                // check: the dropped set must be a subset of the
                // currently-carried capabilities. A caller asking to
                // drop authority they don't hold is either a
                // programming bug or a probing attempt; either way
                // the substrate rejects with a distinct outcome so
                // forensic analysis can separate this from generic
                // IllegalNarrowing.
                if !self.capabilities.is_superset_of(&narrow.drop) {
                    emit_derived_context(
                        self,
                        self.requester.clone(),
                        crate::audit::NarrowingKind::NarrowCapabilities,
                        crate::audit::DerivationOutcome::NarrowingExceedsAuthority,
                        now,
                    );
                    return Err(DeriveError::NarrowingExceedsAuthority);
                }
                (
                    self.requester.clone(),
                    DerivationReason::NarrowCapabilities {
                        dropped: narrow.drop.clone(),
                    },
                    crate::audit::NarrowingKind::NarrowCapabilities,
                    self.capabilities.without(&narrow.drop),
                )
            } else if let Some(svc_to_svc) =
                narrowing_any.downcast_ref::<ServiceToService>()
            {
                // ServiceToService verification (Phase 7e C3):
                // 1. Current ctx.requester must be Service —
                //    otherwise this is structurally illegal
                //    (Did → Service requires a trust declaration
                //    which only a Service can hold).
                let current_svc = match &self.requester {
                    Requester::Service(s) => s.clone(),
                    _ => {
                        let to = Requester::Service(svc_to_svc.target.clone());
                        emit_derived_context(
                            self,
                            to,
                            crate::audit::NarrowingKind::ServiceToService,
                            crate::audit::DerivationOutcome::IllegalNarrowing,
                            now,
                        );
                        return Err(DeriveError::IllegalNarrowing);
                    }
                };
                // 2. Trust declaration's `from_service` must
                //    match the current Service requester.
                if &current_svc != svc_to_svc.trust_declaration.from_service() {
                    let to = Requester::Service(svc_to_svc.target.clone());
                    emit_derived_context(
                        self,
                        to,
                        crate::audit::NarrowingKind::ServiceToService,
                        crate::audit::DerivationOutcome::IllegalNarrowing,
                        now,
                    );
                    return Err(DeriveError::IllegalNarrowing);
                }
                // 3. Trust declaration's `to_service` must match
                //    the narrowing's target.
                if &svc_to_svc.target != svc_to_svc.trust_declaration.to_service() {
                    let to = Requester::Service(svc_to_svc.target.clone());
                    emit_derived_context(
                        self,
                        to,
                        crate::audit::NarrowingKind::ServiceToService,
                        crate::audit::DerivationOutcome::IllegalNarrowing,
                        now,
                    );
                    return Err(DeriveError::IllegalNarrowing);
                }
                // 4. Trust declaration validity window must cover
                //    `now`. Re-check at derive time even though
                //    verify_trust_declaration already checked at
                //    receive time — declarations may have expired
                //    between verification and derivation.
                if now < svc_to_svc.trust_declaration.issued_at()
                    || now >= svc_to_svc.trust_declaration.expires_at()
                {
                    let to = Requester::Service(svc_to_svc.target.clone());
                    emit_derived_context(
                        self,
                        to,
                        crate::audit::NarrowingKind::ServiceToService,
                        crate::audit::DerivationOutcome::UndeclaredServiceTrust,
                        now,
                    );
                    return Err(DeriveError::UndeclaredServiceTrust);
                }
                // ServiceToService delegation: the resulting
                // context's capability set is what the operator-
                // managed trust declaration authorizes — not what
                // the source service held. This is the §7.4 model:
                // trust declarations are authority grants from one
                // service to another, governed by an out-of-band
                // operator-managed root.
                (
                    Requester::Service(svc_to_svc.target.clone()),
                    DerivationReason::ServiceToServiceDelegation {
                        trust_declaration_id: *svc_to_svc
                            .trust_declaration
                            .declaration_id(),
                    },
                    crate::audit::NarrowingKind::ServiceToService,
                    svc_to_svc.trust_declaration.capabilities().clone(),
                )
            } else {
                unreachable!(
                    "Narrowing is sealed; only ToAnonymous / NarrowCapabilities / ServiceToService impl it"
                )
            };

        // Extend the attribution chain with a hop recording the
        // source requester + derivation reason + timestamp.
        let mut new_chain = self.attribution_chain.clone();
        if let Err(e) = new_chain.try_push(AttributionEntry {
            requester: self.requester.clone(),
            derivation_reason,
            derived_at: now,
            key_id_used: None,
        }) {
            // ChainTooDeep — emit failure outcome and propagate.
            emit_derived_context(
                self,
                new_requester,
                narrowing_kind,
                crate::audit::DerivationOutcome::ChainTooDeep,
                now,
            );
            return Err(e);
        }

        // All checks passed — emit Success outcome and return.
        emit_derived_context(
            self,
            new_requester.clone(),
            narrowing_kind,
            crate::audit::DerivationOutcome::Success,
            now,
        );

        Ok(AuthContext::new_internal(
            new_requester,
            self.trace_id,
            self.audit,
            self.oracles,
            new_chain,
            new_capabilities,
        ))
    }
}

/// §4.2 derivation audit-emit helper. Fire-and-forget: sink
/// errors are discarded so derive_for surfaces the derivation
/// outcome (not the audit-infrastructure outcome) to the caller.
fn emit_derived_context(
    ctx: &AuthContext<'_>,
    to: Requester,
    narrowing_kind: crate::audit::NarrowingKind,
    outcome: crate::audit::DerivationOutcome,
    at: SystemTime,
) {
    let event = crate::audit::UserAuditEvent::DerivedContext {
        trace_id: ctx.trace_id,
        from: ctx.requester.clone(),
        to,
        narrowing_kind,
        outcome,
        at,
    };
    // Fire-and-forget: discard the sink result.
    let _ = ctx.audit.user.record(event);
}

/// Resolved requester identity (§4.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    /// Identified user.
    Did(Did),
    /// Substrate-internal or federation service.
    Service(ServiceIdentity),
    /// Anonymous reader.
    Anonymous,
}

impl Requester {
    /// Return the [`RequesterKind`] discriminant.
    ///
    /// Used by the §4.3 issuance chokepoints to surface
    /// requester-class mismatches in [`crate::AuthDenial::RequesterLacksAuthority`]
    /// without leaking the underlying [`Did`] / [`ServiceIdentity`]
    /// payload into the diagnostic.
    #[must_use]
    pub fn kind(&self) -> RequesterKind {
        match self {
            Requester::Did(_) => RequesterKind::Did,
            Requester::Service(_) => RequesterKind::Service,
            Requester::Anonymous => RequesterKind::Anonymous,
        }
    }
}

/// Discriminant variant of [`Requester`] (§4.3).
///
/// Carried by [`crate::AuthDenial::RequesterLacksAuthority`] so
/// stage-1 issuance failures report what kind of requester was
/// found (without leaking the requester identity into the
/// diagnostic).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequesterKind {
    /// User DID.
    Did,
    /// Substrate-internal or federation service.
    Service,
    /// Anonymous reader.
    Anonymous,
}

/// Audit sinks installed at the substrate process boundary
/// (§4.2). Carried by reference inside [`AuthContext`]; the
/// substrate owns the sink lifetimes.
#[derive(Copy, Clone)]
#[non_exhaustive]
pub struct AuditSinks<'a> {
    /// User-class sink.
    pub user: &'a dyn UserAuditSink,
    /// Channel-class sink.
    pub channel: &'a dyn ChannelAuditSink,
    /// Substrate-class sink.
    pub substrate: &'a dyn SubstrateAuditSink,
    /// Moderation-class sink.
    pub moderation: &'a dyn ModerationAuditSink,
    /// Fallback sink for sink-panic / composite-failure events.
    pub fallback: &'a dyn FallbackAuditSink,
    /// §6.7 inspection-notification queue — moderation-class
    /// bind ([`crate::authority::ModerationProof::bind`]) fans
    /// inspection events to the resource owner alongside the
    /// composite-audit moderation emission. Operators not running
    /// an inspection queue install
    /// [`crate::authority::NoInspectionNotifications`].
    ///
    /// Inspection emission is OUTSIDE composite-audit rollback
    /// semantics per §6.7's "notifications are diagnostic, not
    /// authoritative" — see [`InspectionNotificationQueueImpl`]
    /// for the discipline.
    pub inspection_queue: &'a dyn InspectionNotificationQueueImpl,
    /// §4.4 deployment correlation key — channel-class bind
    /// ([`crate::authority::ChannelProof::bind`]) computes
    /// `SessionDigest::compute(session_id, correlation_key)` for
    /// the audit-event `session_digest` field so cross-deployment
    /// session correlation is foreclosed.
    ///
    /// Operators rotate this key infrequently (yearly per §4.4
    /// guidance); rotation invalidates audit correlation across
    /// the rotation boundary, which is the designed effect.
    pub correlation_key: &'a CorrelationKey,
}

/// Oracle set installed at the substrate process boundary
/// (§4.2).
#[derive(Copy, Clone)]
#[non_exhaustive]
pub struct OracleSet<'a> {
    /// Block-state oracle.
    pub block: &'a dyn BlockOracle,
    /// Audience-state oracle.
    pub audience: &'a dyn AudienceOracle,
    /// Mute-state oracle.
    pub mute: &'a dyn MuteOracle,
}

// ============================================================
// AttributionChain.
// ============================================================

/// In-process attribution chain (§4.2).
///
/// Bounded depth via [`MAX_CHAIN_DEPTH`]. Reconstructed on
/// ingress from the wire-side `ClaimOrigin::DelegatedFromUpstream`'s
/// `chain` field (see [`crate::wire::ClaimOrigin`]) after
/// verifying each [`crate::wire::DelegationReceipt`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributionChain {
    entries: SmallVec<[AttributionEntry; MAX_CHAIN_DEPTH]>,
}

impl AttributionChain {
    /// Empty chain.
    #[must_use]
    pub fn empty() -> Self {
        AttributionChain::default()
    }

    /// Borrow the entries.
    #[must_use]
    pub fn entries(&self) -> &[AttributionEntry] {
        &self.entries
    }

    /// Crate-internal append. Enforces [`MAX_CHAIN_DEPTH`].
    pub(crate) fn try_push(&mut self, entry: AttributionEntry) -> Result<(), DeriveError> {
        if self.entries.len() >= MAX_CHAIN_DEPTH {
            return Err(DeriveError::ChainTooDeep);
        }
        self.entries.push(entry);
        Ok(())
    }
}

/// One entry in an [`AttributionChain`] (§4.2).
///
/// Extended in §4.8 round-5 to carry `key_id_used` so subsequent
/// re-verification preserves the historical binding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttributionEntry {
    /// The requester at this hop.
    pub requester: Requester,
    /// Why the prior context narrowed / delegated.
    pub derivation_reason: DerivationReason,
    /// When the derivation happened.
    pub derived_at: SystemTime,
    /// Key id used to sign this hop's delegation receipt, if
    /// applicable. `None` for the originating user / for the
    /// in-process anonymous-derivation case.
    pub key_id_used: Option<crate::identity::KeyId>,
}

/// Reason for an attribution-chain hop (§4.2, §4.8).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationReason {
    /// Authenticated context dropped to anonymous.
    DropPrivilegeToAnonymous,
    /// Capabilities were narrowed; `dropped` records what was
    /// removed.
    NarrowCapabilities {
        /// Capabilities dropped at this hop.
        dropped: CapabilitySet,
    },
    /// Service-to-service delegation. `trust_declaration_id`
    /// names the operator-managed declaration that authorized
    /// the delegation (§7.7).
    ServiceToServiceDelegation {
        /// Operator-managed trust declaration that authorized
        /// the delegation.
        trust_declaration_id: TrustDeclarationId,
    },
}

/// Operator-managed trust declaration identifier (§7.4).
///
/// 128-bit random identifier per §7.4. The substrate verifies
/// signatures, validity windows, and trust-root authority; it
/// does NOT maintain a substrate-side declaration-ID history or
/// check for ID reuse.
///
/// 128 random bits make accidental collision astronomically
/// unlikely. Deliberate reuse requires operator coordination
/// across rotations (which is itself an operator-trust event);
/// operators with revocation needs implement a declaration-status
/// oracle or rely on the validity-window mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustDeclarationId([u8; 16]);

impl TrustDeclarationId {
    /// Construct a [`TrustDeclarationId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        TrustDeclarationId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Failure cases for [`AuthContext::derive_for`] (§4.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeriveError {
    /// Chain depth would exceed [`MAX_CHAIN_DEPTH`].
    #[error("attribution chain too deep")]
    ChainTooDeep,
    /// Narrowing is structurally illegal (e.g., Did → Service
    /// without trust declaration).
    #[error("illegal narrowing")]
    IllegalNarrowing,
    /// `ServiceToService` was requested but no trust declaration
    /// was supplied.
    #[error("undeclared service trust")]
    UndeclaredServiceTrust,
    /// `NarrowCapabilities` requested a drop set that exceeded
    /// the source context's authorized capability set. The
    /// caller asked to drop authority the context did not hold;
    /// this is distinct from [`Self::IllegalNarrowing`] (which
    /// covers structural narrowing misuse) so forensic analysis
    /// can separate "drop set exceeded authority" — a probing
    /// or programming-error pattern — from generic structural
    /// illegality.
    #[error("narrowing exceeds authority")]
    NarrowingExceedsAuthority,
}

// ============================================================
// Narrowing — sealed trait with three impls.
// ============================================================

/// Sealed marker trait for legal sub-context derivations
/// (§4.2). Three impls ship: [`ToAnonymous`],
/// [`NarrowCapabilities`], [`ServiceToService`].
///
/// Sealed via a crate-internal `Sealed` supertrait — outside
/// crates cannot add impls.
///
/// ```compile_fail
/// // Outside the crate this fails: the supertrait is not
/// // nameable, so the impl cannot satisfy its bound.
/// use kryphocron::Narrowing;
/// struct EvilNarrowing;
/// impl Narrowing for EvilNarrowing {}
/// ```
pub trait Narrowing: sealed::Sealed {}

/// Drop authenticated context to anonymous (§4.2).
#[derive(Debug, Clone, Copy)]
pub struct ToAnonymous;

impl sealed::Sealed for ToAnonymous {}
impl Narrowing for ToAnonymous {}

/// Narrow the carried capability set (§4.2).
#[derive(Debug, Clone)]
pub struct NarrowCapabilities {
    /// Capabilities to drop.
    pub drop: CapabilitySet,
}

impl sealed::Sealed for NarrowCapabilities {}
impl Narrowing for NarrowCapabilities {}

/// Service-to-service delegation (§4.2 / §7.6 / §7.7).
#[derive(Debug, Clone)]
pub struct ServiceToService {
    /// Target service identity.
    pub target: ServiceIdentity,
    /// Operator-managed trust declaration that authorizes the
    /// delegation. Phase 1 placeholder; §7.4 commits the shape.
    pub trust_declaration: ServiceTrustDeclaration,
}

impl sealed::Sealed for ServiceToService {}
impl Narrowing for ServiceToService {}

/// Operator-managed trust declaration (§7.4).
///
/// Constructible only via [`crate::trust::verify_trust_declaration`]
/// — every field is private including the
/// `_private: PhantomData<sealed::Token>` marker. Operators
/// receiving a `ServiceTrustDeclaration` need not re-verify or
/// trust the caller; a successful return from
/// `verify_trust_declaration` is the witness that all §7.4
/// verification stages succeeded (signature against a configured
/// trust root, validity window within
/// [`crate::trust::MAX_TRUST_DECLARATION_VALIDITY`], canonical
/// CBOR round-trip, domain separation).
///
/// ```compile_fail
/// // Outside-crate construction must not work — every field is
/// // private.
/// use kryphocron::ingress::ServiceTrustDeclaration;
/// let _v = ServiceTrustDeclaration {
///     // fields private; this fails to compile.
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTrustDeclaration {
    pub(crate) declaration_id: TrustDeclarationId,
    pub(crate) from_service: ServiceIdentity,
    pub(crate) to_service: ServiceIdentity,
    pub(crate) capabilities: CapabilitySet,
    pub(crate) resource_scope: crate::wire::ResourceScope,
    pub(crate) issued_at: SystemTime,
    pub(crate) expires_at: SystemTime,
    pub(crate) trust_root: crate::trust::TrustRootIdentity,
    pub(crate) signature: crate::trust::TrustRootSignature,
    pub(crate) _private: PhantomData<sealed::Token>,
}

impl ServiceTrustDeclaration {
    /// Borrow the declaration id.
    #[must_use]
    pub fn declaration_id(&self) -> &TrustDeclarationId {
        &self.declaration_id
    }
    /// Borrow the from-service identity.
    #[must_use]
    pub fn from_service(&self) -> &ServiceIdentity {
        &self.from_service
    }
    /// Borrow the to-service identity.
    #[must_use]
    pub fn to_service(&self) -> &ServiceIdentity {
        &self.to_service
    }
    /// Borrow the capabilities being delegated.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }
    /// Borrow the resource scope.
    #[must_use]
    pub fn resource_scope(&self) -> &crate::wire::ResourceScope {
        &self.resource_scope
    }
    /// Issued-at instant.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }
    /// Expires-at instant.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    /// Borrow the trust-root identity that signed this declaration.
    #[must_use]
    pub fn trust_root(&self) -> &crate::trust::TrustRootIdentity {
        &self.trust_root
    }
    /// Borrow the trust-root signature.
    #[must_use]
    pub fn signature(&self) -> &crate::trust::TrustRootSignature {
        &self.signature
    }
}

// ============================================================
// Ingress submodule — construct AuthContext from verified
// evidence.
// ============================================================

/// Construct [`AuthContext`] from a verified XRPC JWT (§4.2).
///
/// The resulting context's [`Requester`] is [`Requester::Did`]
/// carrying the JWT's `iss` claim. The attribution chain is
/// empty: an XRPC request IS the origin, so there's no upstream
/// delegation to rehydrate.
///
/// Phase 4e wires this entry point. The JWT scope itself is not
/// projected into the AuthContext at this layer — downstream
/// access-control code consults the [`crate::verification::VerifiedJwt`]
/// directly when it needs to make scope-derived decisions; the
/// AuthContext carries the requester identity, the trace_id, the
/// audit sinks, and the oracles.
///
/// **Capability set:** v0.1 ships this constructor with
/// `AuthContext::capabilities` set to `CapabilitySet::empty()`.
/// JWT scope strings are operator-defined free text (typically
/// NSID-shaped) and do not map structurally to v1's
/// [`crate::authority::capability::CapabilityKind`] enumeration;
/// projecting scope into the
/// capability set would conflate two distinct authority surfaces.
/// A `Requester::Did` constructed via this path therefore cannot
/// legally [`AuthContext::derive_for`] a non-empty
/// `NarrowCapabilities` — the dropped set must be empty (a no-op
/// narrowing, recorded for forensic continuity) or the derivation
/// returns [`DeriveError::NarrowingExceedsAuthority`]. Operators
/// needing scope-aware sub-context derivation consult
/// [`crate::verification::VerifiedJwt::scope`] directly.
#[must_use]
pub fn from_xrpc_request<'a>(
    evidence: crate::verification::VerifiedJwt,
    trace_id: TraceId,
    sinks: AuditSinks<'a>,
    oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    AuthContext::new_internal(
        Requester::Did(evidence.issuer().clone()),
        trace_id,
        sinks,
        oracles,
        AttributionChain::empty(),
        CapabilitySet::empty(),
    )
}

/// Construct [`AuthContext`] from a verified service-issued
/// capability claim (§7.6).
///
/// The resulting context's [`Requester`] is [`Requester::Service`]
/// carrying the claim's issuer identity. The attribution chain is
/// rehydrated from the claim's verified upstream chain (Phase 4e):
///
/// - For `ClaimOrigin::SelfOriginated` claims, the chain is empty
///   — the issuer IS the origin.
/// - For `ClaimOrigin::DelegatedFromUpstream` claims, the
///   verified `crate::AttributionChain` returned by
///   [`crate::verification::verify_attribution_chain`] (carried
///   inside the `VerifiedCapabilityClaim` per Phase 4e C3) is
///   unpacked into the AuthContext.
#[must_use]
pub fn from_service_request<'a>(
    evidence: crate::verification::VerifiedCapabilityClaim,
    trace_id: TraceId,
    sinks: AuditSinks<'a>,
    oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    let issuer = evidence.issuer().clone();
    let chain = evidence.chain().cloned().unwrap_or_else(AttributionChain::empty);
    // v0.1 polish pass 2: project the verified claim's authorized
    // capabilities into the AuthContext so `derive_for(
    // NarrowCapabilities)` can structurally enforce that drops are
    // subsets of what the claim actually authorized.
    let capabilities =
        CapabilitySet::from_kinds(evidence.capabilities().iter().copied());
    AuthContext::new_internal(
        Requester::Service(issuer),
        trace_id,
        sinks,
        oracles,
        chain,
        capabilities,
    )
}

/// Construct [`AuthContext`] from a verified post-handshake
/// sync-channel message (§7.5 / §7.6).
///
/// The resulting context's [`Requester`] is
/// [`Requester::Service`] carrying the session-bound peer
/// identity from the originating handshake. The attribution chain
/// is rehydrated from the inner [`crate::verification::VerifiedCapabilityClaim`]'s
/// verified chain (Phase 4e). The sync-channel hop itself is
/// transport, not delegation, so no extra entry is recorded for
/// it — the `Requester::Service(session_peer)` carries the
/// transport context, while the chain captures upstream
/// delegation history.
///
/// The substrate dispatcher is responsible for the §7.5
/// `UnknownSessionMessage` audit emit when a sync-channel message
/// arrives with a session id not in the local session table — this
/// function operates on already-verified evidence, after the
/// session lookup succeeded and
/// [`crate::verification::verify_sync_message`] returned a
/// [`crate::verification::VerifiedSyncMessage`].
#[must_use]
pub fn from_sync_channel_message<'a>(
    evidence: crate::verification::VerifiedSyncMessage,
    trace_id: TraceId,
    sinks: AuditSinks<'a>,
    oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    let session_identity = evidence.session_identity().clone();
    let chain = evidence
        .payload()
        .chain()
        .cloned()
        .unwrap_or_else(AttributionChain::empty);
    // v0.1 polish pass 2: project the inner verified claim's
    // authorized capabilities. The sync-channel transport doesn't
    // add or remove authority — the capability surface is whatever
    // the inner capability claim carried.
    let capabilities =
        CapabilitySet::from_kinds(evidence.payload().capabilities().iter().copied());
    AuthContext::new_internal(
        Requester::Service(session_identity),
        trace_id,
        sinks,
        oracles,
        chain,
        capabilities,
    )
}

/// Construct an anonymous [`AuthContext`] for public-read paths
/// (§4.2).
///
/// The resulting context's [`Requester`] is
/// [`Requester::Anonymous`]; the attribution chain is empty.
/// Used for public-read code paths where the substrate processes
/// records visible at [`crate::Tier::Public`] without requiring
/// authenticated identity.
///
/// `trace_id` is supplied by the caller — typically a per-request
/// fresh value from the dispatcher's request-id generator. The
/// crate does not generate trace ids internally.
#[must_use]
pub fn anonymous_for_public_read<'a>(
    trace_id: TraceId,
    sinks: AuditSinks<'a>,
    oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    AuthContext::new_internal(
        Requester::Anonymous,
        trace_id,
        sinks,
        oracles,
        AttributionChain::empty(),
        // Anonymous requesters carry no authorized capabilities.
        CapabilitySet::empty(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_chain_depth_pinned_at_8() {
        // §4.2 commits MAX_CHAIN_DEPTH = 8.
        assert_eq!(MAX_CHAIN_DEPTH, 8);
    }

    /// §4.3 stage 1 (Phase 7c): `Requester::kind()` returns the
    /// matching [`RequesterKind`] discriminant for each variant.
    #[test]
    fn requester_kind_discriminant_matches_variant() {
        assert_eq!(
            Requester::Did(Did::new("did:plc:example").unwrap()).kind(),
            RequesterKind::Did
        );
        assert_eq!(Requester::Anonymous.kind(), RequesterKind::Anonymous);
        // Service variant covered indirectly via the issuance tests
        // in src/authority/mod.rs which construct ServiceIdentity
        // values; constructing one here would duplicate that
        // fixture surface.
    }

    #[test]
    fn attribution_chain_rejects_overdepth() {
        let mut chain = AttributionChain::empty();
        for _ in 0..MAX_CHAIN_DEPTH {
            chain
                .try_push(AttributionEntry {
                    requester: Requester::Anonymous,
                    derivation_reason: DerivationReason::DropPrivilegeToAnonymous,
                    derived_at: SystemTime::UNIX_EPOCH,
                    key_id_used: None,
                })
                .unwrap();
        }
        // One more should reject.
        let r = chain.try_push(AttributionEntry {
            requester: Requester::Anonymous,
            derivation_reason: DerivationReason::DropPrivilegeToAnonymous,
            derived_at: SystemTime::UNIX_EPOCH,
            key_id_used: None,
        });
        assert!(matches!(r, Err(DeriveError::ChainTooDeep)));
    }

    // ====================================================
    // Phase 7e C2-C3 — derive_for tests.
    // ====================================================

    mod derive_for_fixture {
        use crate::audit::*;
        use crate::authority::moderation::InspectionNotificationQueueImpl;
        use crate::oracle::*;
        use std::sync::Mutex;
        use std::time::{Duration, SystemTime};

        /// Capturing user sink for verifying DerivedContext audit
        /// emits in C3.
        pub(super) struct CapturingUserSink {
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

        pub(super) struct NoSink;
        impl ChannelAuditSink for NoSink {
            fn record(&self, _: ChannelAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl SubstrateAuditSink for NoSink {
            fn record(&self, _: SubstrateAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl ModerationAuditSink for NoSink {
            fn record(&self, _: ModerationAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl FallbackAuditSink for NoSink {
            fn record_panic(
                &self,
                _: SinkKind,
                _: crate::identity::TraceId,
                _: crate::authority::CapabilityKind,
                _: SystemTime,
            ) {
            }
            fn record_composite_failure(
                &self,
                _: crate::identity::TraceId,
                _: CompositeOpId,
                _: &[SinkKind],
                _: &[SinkKind],
                _: SystemTime,
            ) {
            }
            fn record_event(&self, _: FallbackAuditEvent) {}
        }
        impl InspectionNotificationQueueImpl for NoSink {
            fn enqueue(
                &self,
                _: &crate::proto::Did,
                _: crate::authority::InspectionNotification,
            ) {
            }
        }

        /// User sink that always fails (for fire-and-forget tests
        /// in C3).
        pub(super) struct FailingUserSink;
        impl UserAuditSink for FailingUserSink {
            fn record(&self, _: UserAuditEvent) -> Result<(), AuditError> {
                Err(AuditError::Unavailable)
            }
        }

        pub(super) struct NoOracle;
        impl BlockOracle for NoOracle {
            fn block_state(
                &self,
                _: &crate::proto::Did,
                _: &crate::proto::Did,
            ) -> BlockState {
                BlockState::None
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
        impl AudienceOracle for NoOracle {
            fn audience_state(
                &self,
                _: &crate::proto::Did,
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
        impl MuteOracle for NoOracle {
            fn mute_state(
                &self,
                _: &crate::proto::Did,
                _: &crate::proto::Did,
            ) -> MuteState {
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
    }

    use derive_for_fixture::*;

    fn sample_did() -> Did {
        Did::new("did:plc:phase7e-derive").unwrap()
    }

    fn sample_service() -> crate::identity::ServiceIdentity {
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

    fn build_ctx<'a>(
        user_sink: &'a dyn UserAuditSink,
        no_sink: &'a NoSink,
        no_oracle: &'a NoOracle,
        correlation_key: &'a crate::identity::CorrelationKey,
        requester: Requester,
    ) -> AuthContext<'a> {
        build_ctx_with_caps(
            user_sink,
            no_sink,
            no_oracle,
            correlation_key,
            requester,
            crate::authority::capability::CapabilitySet::empty(),
        )
    }

    /// Tests that need to seed the AuthContext with a non-empty
    /// capability set (so they can exercise the v0.1-polish-pass-2
    /// superset check in `derive_for(NarrowCapabilities)`) use
    /// this builder. Everything else delegates here via
    /// `build_ctx` with an empty set.
    fn build_ctx_with_caps<'a>(
        user_sink: &'a dyn UserAuditSink,
        no_sink: &'a NoSink,
        no_oracle: &'a NoOracle,
        correlation_key: &'a crate::identity::CorrelationKey,
        requester: Requester,
        capabilities: crate::authority::capability::CapabilitySet,
    ) -> AuthContext<'a> {
        AuthContext::new_internal(
            requester,
            crate::identity::TraceId::from_bytes([0xEE; 16]),
            AuditSinks {
                user: user_sink,
                channel: no_sink,
                substrate: no_sink,
                moderation: no_sink,
                fallback: no_sink,
                inspection_queue: no_sink,
                correlation_key,
            },
            OracleSet {
                block: no_oracle,
                audience: no_oracle,
                mute: no_oracle,
            },
            AttributionChain::empty(),
            capabilities,
        )
    }

    /// §4.2 ToAnonymous from a Did context: new ctx is Anonymous,
    /// chain extended by 1 with DropPrivilegeToAnonymous.
    #[test]
    fn derive_for_to_anonymous_from_did() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
        );

        let derived = ctx.derive_for(ToAnonymous).expect("ToAnonymous should succeed");
        assert!(matches!(derived.requester(), Requester::Anonymous));
        assert_eq!(derived.attribution_chain().entries().len(), 1);
        match &derived.attribution_chain().entries()[0].derivation_reason {
            DerivationReason::DropPrivilegeToAnonymous => {}
            other => panic!("expected DropPrivilegeToAnonymous, got {other:?}"),
        }
        // Audit emit lands in C3; C2 leaves the user sink empty.
    }

    /// §4.2 ToAnonymous from a Service context: new ctx is
    /// Anonymous; chain records the source Service.
    #[test]
    fn derive_for_to_anonymous_from_service() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc = sample_service();
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Service(svc.clone()),
        );

        let derived = ctx.derive_for(ToAnonymous).unwrap();
        assert!(matches!(derived.requester(), Requester::Anonymous));
        let entries = derived.attribution_chain().entries();
        assert_eq!(entries.len(), 1);
        // Source requester captured (Service)
        assert!(matches!(&entries[0].requester, Requester::Service(_)));
    }

    /// §4.2 ToAnonymous from already-Anonymous: idempotent
    /// happy-path. Chain still grows by 1 (the derivation hop is
    /// recorded regardless of whether requester actually changed).
    #[test]
    fn derive_for_to_anonymous_from_anonymous() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(&user, &no_sink, &no_oracle, &ck, Requester::Anonymous);

        let derived = ctx.derive_for(ToAnonymous).unwrap();
        assert!(matches!(derived.requester(), Requester::Anonymous));
        assert_eq!(derived.attribution_chain().entries().len(), 1);
    }

    /// §4.2 NarrowCapabilities happy path (v0.1 polish pass 2:
    /// evolved from Phase 7e's recording-only fixture).
    /// Requester unchanged, chain records the dropped
    /// capabilities, AND the post-narrowing AuthContext's
    /// capability set equals the source set minus the drop.
    #[test]
    fn derive_for_narrow_capabilities() {
        use crate::authority::capability::{CapabilityKind, CapabilitySet};

        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let did = sample_did();
        // Seed the source context with two capabilities so the drop
        // exercises both subset enforcement (passes) and difference
        // computation (one remains).
        let initial = CapabilitySet::from_kinds([
            CapabilityKind::ViewPrivate,
            CapabilityKind::EditPrivatePost,
        ]);
        let ctx = build_ctx_with_caps(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(did.clone()),
            initial.clone(),
        );

        let dropped = CapabilitySet::from_kinds([CapabilityKind::EditPrivatePost]);
        let derived = ctx
            .derive_for(NarrowCapabilities {
                drop: dropped.clone(),
            })
            .unwrap();

        // Requester unchanged
        match derived.requester() {
            Requester::Did(d) => assert_eq!(d, &did),
            other => panic!("expected Did(unchanged), got {other:?}"),
        }
        // Chain records the dropped capabilities
        let entries = derived.attribution_chain().entries();
        assert_eq!(entries.len(), 1);
        match &entries[0].derivation_reason {
            DerivationReason::NarrowCapabilities { dropped: d } => {
                assert_eq!(d, &dropped);
            }
            other => panic!("expected NarrowCapabilities, got {other:?}"),
        }
        // v0.1 polish pass 2: the resulting capability set is the
        // source set minus the drop.
        let expected_after =
            CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]);
        assert_eq!(derived.capabilities(), &expected_after);
    }

    /// v0.1 polish pass 2: `NarrowCapabilities` whose drop set is
    /// NOT a subset of the source context's authorized
    /// capabilities fails closed with
    /// `DeriveError::NarrowingExceedsAuthority`. The caller asked
    /// to drop authority they don't hold — a probing pattern.
    #[test]
    fn derive_for_narrow_capabilities_rejects_superset() {
        use crate::authority::capability::{CapabilityKind, CapabilitySet};

        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        // Source holds only ViewPrivate.
        let initial = CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]);
        let ctx = build_ctx_with_caps(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
            initial,
        );

        // Drop targets BOTH ViewPrivate AND EditPrivatePost — the
        // second is not held, so the drop set exceeds authority.
        let exceeding = CapabilitySet::from_kinds([
            CapabilityKind::ViewPrivate,
            CapabilityKind::EditPrivatePost,
        ]);
        let result = ctx.derive_for(NarrowCapabilities { drop: exceeding });
        assert!(matches!(result, Err(DeriveError::NarrowingExceedsAuthority)));
    }

    /// v0.1 polish pass 2 boundary: `NarrowCapabilities { drop:
    /// CapabilitySet::empty() }` is a legal no-op against any
    /// source set (the empty set is a subset of every set).
    /// The chain entry is still recorded for forensic
    /// continuity, and the resulting capability set equals the
    /// source unchanged. This pins the boundary so a future
    /// refactor doesn't accidentally treat empty-drop as a
    /// special case that bypasses chain recording.
    #[test]
    fn derive_for_narrow_capabilities_empty_drop_is_noop() {
        use crate::authority::capability::{CapabilityKind, CapabilitySet};

        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let initial = CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]);
        let ctx = build_ctx_with_caps(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
            initial.clone(),
        );

        let derived = ctx
            .derive_for(NarrowCapabilities {
                drop: CapabilitySet::empty(),
            })
            .unwrap();
        // Capabilities unchanged.
        assert_eq!(derived.capabilities(), &initial);
        // Chain entry recorded with empty dropped set.
        let entries = derived.attribution_chain().entries();
        assert_eq!(entries.len(), 1);
        match &entries[0].derivation_reason {
            DerivationReason::NarrowCapabilities { dropped } => {
                assert!(dropped.is_empty());
            }
            other => panic!("expected NarrowCapabilities, got {other:?}"),
        }
    }

    /// v0.1 polish pass 2: §4.2's "audit reflects action, not
    /// intent" discipline — a failed superset-narrowing must
    /// still emit a DerivedContext audit event with the
    /// `NarrowingExceedsAuthority` outcome, so forensic analysis
    /// captures the rejected attempt distinct from
    /// IllegalNarrowing.
    #[test]
    fn derive_for_narrow_capabilities_failed_superset_emits_audit() {
        use crate::authority::capability::{CapabilityKind, CapabilitySet};

        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx_with_caps(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
            CapabilitySet::empty(),
        );

        let exceeding =
            CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]);
        let _ = ctx.derive_for(NarrowCapabilities { drop: exceeding });

        // Exactly one DerivedContext event with the
        // NarrowingExceedsAuthority outcome.
        let events = user.captured();
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::audit::UserAuditEvent::DerivedContext {
                narrowing_kind,
                outcome,
                ..
            } => {
                assert_eq!(
                    *narrowing_kind,
                    crate::audit::NarrowingKind::NarrowCapabilities
                );
                assert_eq!(
                    *outcome,
                    crate::audit::DerivationOutcome::NarrowingExceedsAuthority
                );
            }
            other => panic!(
                "expected DerivedContext with NarrowingExceedsAuthority, got {other:?}"
            ),
        }
    }

    /// §4.2 attribution chain monotonicity: derive_for preserves
    /// existing entries and appends a new one. No mutation of
    /// previous entries.
    #[test]
    fn derive_for_preserves_attribution_chain() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx_a = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
        );
        let ctx_b = ctx_a.derive_for(ToAnonymous).unwrap();
        // Now ctx_b has a chain of 1. Derive again from ctx_b.
        let ctx_c = ctx_b.derive_for(ToAnonymous).unwrap();
        let entries = ctx_c.attribution_chain().entries();
        assert_eq!(entries.len(), 2, "chain extends, doesn't replace");
        assert!(matches!(
            entries[0].derivation_reason,
            DerivationReason::DropPrivilegeToAnonymous
        ));
        assert!(matches!(
            entries[1].derivation_reason,
            DerivationReason::DropPrivilegeToAnonymous
        ));
        // ctx_b's source requester was Did
        assert!(matches!(entries[0].requester, Requester::Did(_)));
        // ctx_c's source requester was Anonymous (after ctx_b's
        // ToAnonymous derivation)
        assert!(matches!(entries[1].requester, Requester::Anonymous));
    }

    /// §4.2 ChainTooDeep: filling the chain to MAX_CHAIN_DEPTH
    /// then attempting another derivation returns ChainTooDeep
    /// from try_push (propagated via `?`).
    #[test]
    fn derive_for_returns_chain_too_deep_at_max() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);

        // Build a context whose chain is already at MAX_CHAIN_DEPTH.
        let mut chain = AttributionChain::empty();
        for _ in 0..MAX_CHAIN_DEPTH {
            chain
                .try_push(AttributionEntry {
                    requester: Requester::Anonymous,
                    derivation_reason: DerivationReason::DropPrivilegeToAnonymous,
                    derived_at: SystemTime::UNIX_EPOCH,
                    key_id_used: None,
                })
                .unwrap();
        }
        let ctx = AuthContext::new_internal(
            Requester::Did(sample_did()),
            crate::identity::TraceId::from_bytes([0u8; 16]),
            AuditSinks {
                user: &user,
                channel: &no_sink,
                substrate: &no_sink,
                moderation: &no_sink,
                fallback: &no_sink,
                inspection_queue: &no_sink,
                correlation_key: &ck,
            },
            OracleSet {
                block: &no_oracle,
                audience: &no_oracle,
                mute: &no_oracle,
            },
            chain,
            crate::authority::capability::CapabilitySet::empty(),
        );

        let r = ctx.derive_for(ToAnonymous);
        assert!(matches!(r, Err(DeriveError::ChainTooDeep)));
    }

    // -------- C3 — ServiceToService + DerivedContext audit emit --------

    fn make_service(did_str: &str) -> crate::identity::ServiceIdentity {
        crate::identity::ServiceIdentity::new_internal(
            Did::new(did_str).unwrap(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    /// Build a placeholder verified ServiceTrustDeclaration. Direct
    /// crate-internal construction (we're in src/ingress.rs so the
    /// pub(crate) fields are reachable). verify_trust_declaration
    /// requires a real signature path which is out of scope for
    /// derive_for tests; what derive_for actually checks is the
    /// from/to/window invariants — not the signature.
    fn make_trust_declaration(
        from: crate::identity::ServiceIdentity,
        to: crate::identity::ServiceIdentity,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> ServiceTrustDeclaration {
        ServiceTrustDeclaration {
            declaration_id: TrustDeclarationId::from_bytes([0xAB; 16]),
            from_service: from,
            to_service: to,
            capabilities: crate::authority::capability::CapabilitySet::empty(),
            resource_scope: crate::wire::ResourceScope::Resource(
                crate::authority::ResourceId::new(
                    sample_did(),
                    crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
                    crate::proto::Rkey::new("3jzfcijpj2z2a").unwrap(),
                ),
            ),
            issued_at,
            expires_at,
            trust_root: crate::trust::TrustRootIdentity {
                root_key_id: crate::identity::KeyId::from_bytes([0u8; 32]),
                root_key: crate::identity::PublicKey {
                    algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                    bytes: [0u8; 32],
                },
            },
            signature: crate::trust::TrustRootSignature {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 64],
            },
            _private: PhantomData,
        }
    }

    /// §4.2 / §7.7 happy path: Service A derives to Service B
    /// using a valid trust declaration.
    #[test]
    fn derive_for_service_to_service_happy() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc_a = make_service("did:plc:phase7e-svc-a");
        let svc_b = make_service("did:plc:phase7e-svc-b");
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Service(svc_a.clone()),
        );

        let now = SystemTime::now();
        let decl = make_trust_declaration(
            svc_a.clone(),
            svc_b.clone(),
            now - std::time::Duration::from_secs(60),
            now + std::time::Duration::from_secs(86400),
        );
        let sts = ServiceToService {
            target: svc_b.clone(),
            trust_declaration: decl,
        };

        let derived = ctx.derive_for(sts).expect("happy path should succeed");
        match derived.requester() {
            Requester::Service(s) => assert_eq!(s, &svc_b),
            other => panic!("expected Service(B), got {other:?}"),
        }
        let entries = derived.attribution_chain().entries();
        assert_eq!(entries.len(), 1);
        match &entries[0].derivation_reason {
            DerivationReason::ServiceToServiceDelegation { trust_declaration_id } => {
                assert_eq!(trust_declaration_id.as_bytes(), &[0xAB; 16]);
            }
            other => panic!("expected ServiceToServiceDelegation, got {other:?}"),
        }
    }

    /// §4.2 IllegalNarrowing: ServiceToService from a Did context
    /// is rejected (only Service can hold a trust declaration).
    #[test]
    fn derive_for_service_to_service_from_did_rejected() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc_a = make_service("did:plc:phase7e-svc-a");
        let svc_b = make_service("did:plc:phase7e-svc-b");
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
        );

        let now = SystemTime::now();
        let decl = make_trust_declaration(
            svc_a,
            svc_b.clone(),
            now - std::time::Duration::from_secs(60),
            now + std::time::Duration::from_secs(86400),
        );
        let sts = ServiceToService {
            target: svc_b,
            trust_declaration: decl,
        };
        assert!(matches!(
            ctx.derive_for(sts),
            Err(DeriveError::IllegalNarrowing)
        ));
    }

    /// §4.2 IllegalNarrowing: trust declaration's from_service
    /// must match the current Service requester. Mismatch → reject.
    #[test]
    fn derive_for_service_to_service_from_service_mismatch_rejected() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc_a = make_service("did:plc:phase7e-svc-a");
        let svc_b = make_service("did:plc:phase7e-svc-b");
        let svc_c = make_service("did:plc:phase7e-svc-c");
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Service(svc_a),
        );

        let now = SystemTime::now();
        let decl = make_trust_declaration(
            svc_b, // from
            svc_c.clone(),
            now - std::time::Duration::from_secs(60),
            now + std::time::Duration::from_secs(86400),
        );
        let sts = ServiceToService {
            target: svc_c,
            trust_declaration: decl,
        };
        assert!(matches!(
            ctx.derive_for(sts),
            Err(DeriveError::IllegalNarrowing)
        ));
    }

    /// §4.2 UndeclaredServiceTrust: trust declaration past its
    /// expires_at is rejected even if other invariants hold. Pin
    /// the validity-window re-check at derive time (declarations
    /// may have expired between verify_trust_declaration and
    /// derive_for).
    #[test]
    fn derive_for_service_to_service_expired_declaration_rejected() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc_a = make_service("did:plc:phase7e-svc-a");
        let svc_b = make_service("did:plc:phase7e-svc-b");
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Service(svc_a.clone()),
        );

        let now = SystemTime::now();
        let decl = make_trust_declaration(
            svc_a,
            svc_b.clone(),
            now - std::time::Duration::from_secs(7200),
            now - std::time::Duration::from_secs(3600),
        );
        let sts = ServiceToService {
            target: svc_b,
            trust_declaration: decl,
        };
        assert!(matches!(
            ctx.derive_for(sts),
            Err(DeriveError::UndeclaredServiceTrust)
        ));
    }

    /// §4.2 audit emit: every derivation attempt emits exactly
    /// one DerivedContext event. Verify Success path for all three
    /// narrowings.
    #[test]
    fn derive_for_emits_derived_context_on_success() {
        use crate::audit::{DerivationOutcome, NarrowingKind, UserAuditEvent};

        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc_a = make_service("did:plc:phase7e-emit-a");
        let svc_b = make_service("did:plc:phase7e-emit-b");
        let ctx = build_ctx(
            &user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Service(svc_a.clone()),
        );

        let _ = ctx.derive_for(ToAnonymous).unwrap();
        let _ = ctx
            .derive_for(NarrowCapabilities {
                drop: crate::authority::capability::CapabilitySet::empty(),
            })
            .unwrap();
        let now = SystemTime::now();
        let decl = make_trust_declaration(
            svc_a,
            svc_b.clone(),
            now - std::time::Duration::from_secs(60),
            now + std::time::Duration::from_secs(86400),
        );
        let _ = ctx
            .derive_for(ServiceToService {
                target: svc_b,
                trust_declaration: decl,
            })
            .unwrap();

        let captured = user.captured();
        assert_eq!(captured.len(), 3, "one DerivedContext per derive_for call");
        let kinds: Vec<NarrowingKind> = captured
            .iter()
            .map(|e| match e {
                UserAuditEvent::DerivedContext { narrowing_kind, .. } => *narrowing_kind,
                other => panic!("expected DerivedContext, got {other:?}"),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                NarrowingKind::ToAnonymous,
                NarrowingKind::NarrowCapabilities,
                NarrowingKind::ServiceToService,
            ],
        );
        for event in &captured {
            match event {
                UserAuditEvent::DerivedContext { outcome, .. } => {
                    assert_eq!(*outcome, DerivationOutcome::Success);
                }
                _ => unreachable!(),
            }
        }
    }

    /// §4.2 audit emit on failure: failed derivations emit a
    /// DerivedContext with the matching DerivationOutcome variant.
    #[test]
    fn derive_for_emits_derived_context_on_failure() {
        use crate::audit::{DerivationOutcome, UserAuditEvent};

        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc_a = make_service("did:plc:phase7e-fail-a");
        let svc_b = make_service("did:plc:phase7e-fail-b");
        let ctx = build_ctx(&user, &no_sink, &no_oracle, &ck, Requester::Anonymous);

        let now = SystemTime::now();
        let decl = make_trust_declaration(
            svc_a,
            svc_b.clone(),
            now - std::time::Duration::from_secs(60),
            now + std::time::Duration::from_secs(86400),
        );
        let _ = ctx.derive_for(ServiceToService {
            target: svc_b,
            trust_declaration: decl,
        });

        let captured = user.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            UserAuditEvent::DerivedContext { outcome, .. } => {
                assert_eq!(*outcome, DerivationOutcome::IllegalNarrowing);
            }
            other => panic!("expected DerivedContext, got {other:?}"),
        }
    }

    /// §4.2 fire-and-forget: if the user sink rejects the
    /// DerivedContext event, derive_for still returns Ok with the
    /// new context. Audit infrastructure failure does not block
    /// runtime correctness.
    #[test]
    fn derive_for_audit_emit_failure_does_not_block_derivation() {
        let failing_user = FailingUserSink;
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(
            &failing_user,
            &no_sink,
            &no_oracle,
            &ck,
            Requester::Did(sample_did()),
        );
        let derived = ctx.derive_for(ToAnonymous);
        assert!(
            derived.is_ok(),
            "audit emit failure should not block derivation"
        );
        let derived = derived.unwrap();
        assert!(matches!(derived.requester(), Requester::Anonymous));
    }

    /// §4.2 anonymous_for_public_read constructor (Phase 7f
    /// Bucket D2): produces an AuthContext with
    /// Requester::Anonymous, empty attribution chain, and the
    /// caller-supplied trace_id / sinks / oracles passed through
    /// verbatim.
    #[test]
    fn anonymous_for_public_read_constructs_anonymous_context() {
        let user = CapturingUserSink::new();
        let no_sink = NoSink;
        let no_oracle = NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let trace_id = crate::identity::TraceId::from_bytes([0xAA; 16]);

        let ctx = anonymous_for_public_read(
            trace_id,
            AuditSinks {
                user: &user,
                channel: &no_sink,
                substrate: &no_sink,
                moderation: &no_sink,
                fallback: &no_sink,
                inspection_queue: &no_sink,
                correlation_key: &ck,
            },
            OracleSet {
                block: &no_oracle,
                audience: &no_oracle,
                mute: &no_oracle,
            },
        );

        assert!(matches!(ctx.requester(), Requester::Anonymous));
        assert_eq!(ctx.trace_id(), trace_id);
        assert_eq!(
            ctx.attribution_chain().entries().len(),
            0,
            "anonymous context starts with empty chain"
        );
        // Constructor doesn't fire any audit events.
        assert_eq!(user.captured().len(), 0);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.3 predicate machinery, denial reasons, bind outcomes.

use core::marker::PhantomData;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::authority::capability::{CapabilityClass, UserCapability};
use crate::identity::TraceId;
use crate::ingress::{AttributionChain, Requester, RequesterKind};
use crate::oracle::{
    AudienceOracleQuery, AudienceState, BlockOracleQuery, BlockState, OracleKind,
    OracleQueryKind,
};
use crate::sealed;
use crate::wire::ReceiptVerificationFailure;

/// Reason a capability binding was denied (§4.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// A block-oracle consultation produced a denying state.
    Blocked {
        /// The query that produced the denial.
        query: BlockOracleQuery,
        /// The block state observed.
        state: BlockState,
    },
    /// An audience-oracle consultation produced a denying state.
    NotInAudience {
        /// The query that produced the denial.
        query: AudienceOracleQuery,
        /// The audience state observed.
        state: AudienceState,
    },
    /// An ownership check failed inside a capability's predicate.
    OwnershipCheckFailed,
    /// A capability-specific predicate denied with an inline
    /// rationale.
    CapabilityPredicateRejected {
        /// Static rationale string (operator-visible).
        detail: &'static str,
    },
    /// A capability predicate panicked. Translated to a closed
    /// denial; the panic does not propagate.
    PredicatePanic,
    /// §7.2 extension: a JWT scope did not include the required
    /// value at the capability-issuance chokepoint.
    JwtScopeInsufficient {
        /// Operator-defined required scope.
        required: String,
        /// Granted scope set (may be empty; empty fails closed).
        granted: smallvec::SmallVec<[String; 4]>,
    },
    /// §7.2 extension: a JWT failed verification before reaching
    /// the capability-issuance chokepoint.
    JwtVerificationFailed(crate::verification::JwtVerificationError),
    /// §4.8 W11 / W12 / W13: wire-claim attribution chain failed
    /// receipt verification at the indicated hop.
    AttributionReceiptInvalid {
        /// Zero-based index of the first failing hop.
        failing_hop: u8,
        /// The specific verification failure.
        reason: ReceiptVerificationFailure,
    },
    /// §4.3 stage 0 / §5.6: bind attempted against a deprecated
    /// lexicon. Mirrors the issuance-side
    /// [`AuthDenial::WriteToDeprecatedLexicon`] payload — the
    /// bind path surfaces the same forensic detail (deprecated
    /// NSID, deprecation version, successor if committed) via
    /// the [`BindError::DeniedAtPipeline`] /
    /// [`BindOutcomeRepr::DeniedAtPipeline`] envelope.
    CapabilityDeprecated {
        /// The deprecated NSID the bind targeted.
        nsid: &'static str,
        /// Lexicon-set version the deprecation landed in.
        since_version: SemVer,
        /// Successor NSID, if one is committed.
        successor: Option<&'static str>,
    },
}

/// Pipeline stage where a binding was denied (§4.3).
///
/// Extended in §7.2 with `JwtScope`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipelineStage {
    /// Stage 0: lexicon deprecation gate (§5.6).
    DeprecationGate,
    /// Stage 1: record-state check (Live; delegated to storage).
    RecordState,
    /// Stage 2: block-oracle consultations.
    BlockConsultation,
    /// Stage 3: audience-oracle consultations.
    AudienceConsultation,
    /// Stage 5: capability-specific predicate.
    Predicate,
    /// §7.2 extension: JWT-scope match.
    JwtScope,
}

/// Audit-visible binding outcome (§4.3 `BindOutcomeRepr`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcomeRepr {
    /// Binding succeeded.
    Success,
    /// Subject in the proof did not match the target supplied to
    /// `bind`.
    TargetMismatch,
    /// Context (requester / class) did not match.
    ContextMismatch,
    /// Proof expired between issuance and binding.
    Expired {
        /// When the proof was issued.
        issued_at: Instant,
        /// Maximum age applied to this binding.
        max_age: Duration,
    },
    /// An oracle's freshness commitment was past its bound.
    OracleStale {
        /// Which oracle.
        oracle: OracleKind,
        /// The specific query that was stale.
        query: OracleQueryKind,
        /// Age of the oracle's data at the failed check.
        ///
        /// `Duration::ZERO` is the **clock-skew sentinel**: when the
        /// oracle's `last_synced_at` is future-dated (clock skew, or a
        /// peer reporting forward time), `duration_since` cannot yield
        /// an honest age, so the freshness check fails closed and
        /// reports `ZERO` here rather than a misleading positive age.
        /// An operator reading the audit log treats `sync_age == 0` on
        /// an `OracleStale` outcome as "future-dated sync", not "fresh".
        sync_age: Duration,
    },
    /// A pipeline stage denied.
    DeniedAtPipeline {
        /// Stage that denied.
        stage: PipelineStage,
        /// Reason carried by the stage.
        reason: DenialReason,
    },
}

/// Public `bind` failure (§4.3).
///
/// `bind` returns either `Ok(BoundUserProof<…>)` on success or
/// `Err(BindError)` on any non-success outcome.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BindError {
    /// Target mismatch.
    #[error("bind target mismatch")]
    TargetMismatch,
    /// Context mismatch.
    #[error("bind context mismatch")]
    ContextMismatch,
    /// Proof expired.
    #[error("bind: proof expired")]
    Expired,
    /// Oracle stale.
    #[error("bind: oracle stale ({oracle:?})")]
    OracleStale {
        /// Which oracle.
        oracle: OracleKind,
        /// Specific query.
        query: OracleQueryKind,
    },
    /// Audit sink was unavailable; binding failed closed.
    #[error("bind: audit unavailable")]
    AuditUnavailable,
    /// Audit sink panicked; binding failed closed.
    #[error("bind: audit sink panicked")]
    AuditPanicked,
    /// §4.8 W11 / W12 / W13: attribution receipt verification
    /// failed at `failing_hop` with `reason`. Round-5 patch.
    #[error("bind: attribution receipt invalid at hop {failing_hop}")]
    AttributionReceiptInvalid {
        /// Zero-based index of the first failing hop.
        failing_hop: u8,
        /// Specific verification failure.
        reason: ReceiptVerificationFailure,
    },
    /// §4.3 stage failure: a §4.3 bind pipeline stage produced a
    /// structured denial.
    ///
    /// `stage` names which stage denied (DeprecationGate,
    /// BlockConsultation, AudienceConsultation, Predicate, etc.)
    /// and `reason` carries the per-stage diagnostic. Mirrors the
    /// audit-side rendering [`BindOutcomeRepr::DeniedAtPipeline`].
    #[error("bind denied at {stage:?}: {reason:?}")]
    DeniedAtPipeline {
        /// Stage that denied.
        stage: PipelineStage,
        /// Reason carried by the stage.
        reason: DenialReason,
    },
}

/// Surface `composite_audit` failures as bind errors.
///
/// Bind paths run their pipeline inside [`crate::audit::composite_audit`]
/// (§4.9) and need a `From<CompositeAuditError>` impl on
/// [`BindError`] so the `?` operator propagates audit-machinery
/// failures into the bind-error channel.
///
/// Mapping:
/// - [`crate::audit::CompositeAuditError::SinkCommitFailed`] →
///   [`BindError::AuditUnavailable`] (a sink rejected the event).
/// - [`crate::audit::CompositeAuditError::RollbackDispatchFailed`] →
///   [`BindError::AuditUnavailable`] (rollback dispatch failed
///   after a commit failure; same surface).
/// - [`crate::audit::CompositeAuditError::InconsistencyUnrecoverable`] →
///   [`BindError::AuditPanicked`] (the fallback sink itself
///   panicked — last-resort variant).
/// - [`crate::audit::CompositeAuditError::TrackerFull`] →
///   [`BindError::AuditUnavailable`] (reserved per-process
///   tracker full; same surface).
impl From<crate::audit::CompositeAuditError> for BindError {
    fn from(e: crate::audit::CompositeAuditError) -> Self {
        use crate::audit::CompositeAuditError;
        match e {
            CompositeAuditError::SinkCommitFailed { .. }
            | CompositeAuditError::RollbackDispatchFailed { .. }
            | CompositeAuditError::TrackerFull => BindError::AuditUnavailable,
            CompositeAuditError::InconsistencyUnrecoverable => BindError::AuditPanicked,
        }
    }
}

/// Reborrow-specific failure (§4.3 reborrow re-checks expiry).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BindFailureReason {
    /// Proof expired between bind and reborrow.
    #[error("reborrow: proof expired")]
    Expired,
    /// Oracle freshness violated between bind and reborrow.
    #[error("reborrow: oracle stale")]
    OracleStale {
        /// Which oracle.
        oracle: OracleKind,
        /// Specific query.
        query: OracleQueryKind,
    },
    /// Audit sink unavailable on reborrow.
    #[error("reborrow: audit unavailable")]
    AuditUnavailable,
}

/// Issuance-side denial (§4.3 `AuthDenial`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthDenial {
    /// Two-tier per-issuer rate limiter rejected.
    #[error("issuance rate-limited")]
    RateLimited,
    /// Oracle freshness violated at issuance.
    #[error("issuance: oracle stale ({oracle:?})")]
    OracleStale {
        /// Which oracle.
        oracle: OracleKind,
        /// Specific query.
        query: OracleQueryKind,
    },
    /// Pipeline produced a denial reason.
    #[error("issuance denied")]
    Denied(DenialReason),
    /// Audit sink unavailable; issuance failed closed.
    #[error("issuance: audit unavailable")]
    AuditUnavailable,
    /// Predicate panicked.
    #[error("issuance: predicate panicked")]
    PredicatePanic,
    /// §5.6: write to a deprecated lexicon.
    #[error(
        "issuance: write to deprecated lexicon {nsid} (deprecated since {since_version:?})"
    )]
    WriteToDeprecatedLexicon {
        /// The deprecated NSID.
        nsid: &'static str,
        /// Version at which deprecation took effect.
        since_version: SemVer,
        /// Successor NSID, if one is committed.
        successor: Option<&'static str>,
    },
    /// §7.2 extension: scope did not match required value.
    #[error("issuance: scope mismatch")]
    ScopeMismatch {
        /// Required scope value.
        required: String,
        /// Granted scope set.
        granted: smallvec::SmallVec<[String; 4]>,
    },
    /// §4.3 stage 1: the requester does not carry the authority
    /// required to issue a capability of this class.
    ///
    /// User-class and channel-class accept [`RequesterKind::Did`]
    /// and [`RequesterKind::Service`]. Substrate-class and
    /// moderation-class accept only [`RequesterKind::Service`]
    /// (per §4.6 read-everything-authority discipline and §4.3
    /// moderation-as-service discipline). [`RequesterKind::Anonymous`]
    /// fails for every class.
    #[error("issuance: requester (kind {found:?}) lacks authority to issue {class:?}-class")]
    RequesterLacksAuthority {
        /// The capability class being requested.
        class: CapabilityClass,
        /// The requester kind found.
        found: RequesterKind,
    },
}

/// Semantic-version triplet used in deprecation state (§5.6).
///
/// Re-exported from `kryphocron-lexicons` so the
/// `KRYPHOCRON_LEXICON_REGISTRY` constant and
/// `AuthDenial::WriteToDeprecatedLexicon` use the same shape
/// without a duplicate type definition.
pub use kryphocron_lexicons::SemVer;

/// Predicate-time evaluation context (§4.3 `PredicateContext`).
///
/// Constructors are crate-private. Predicates **cannot**
/// re-consult oracles or emit audit; they consume pre-fetched
/// oracle results and apply capability-specific logic only.
pub struct PredicateContext<'a> {
    requester: &'a Requester,
    trace_id: TraceId,
    attribution_chain: &'a AttributionChain,
    _no_oracles: PhantomData<()>,
    _no_sinks: PhantomData<()>,
    _private: PhantomData<sealed::Token>,
}

impl<'a> PredicateContext<'a> {
    /// Crate-internal constructor. Consumed by
    /// [`crate::UserProof::bind`]'s pipeline at stage 5
    /// (predicate evaluation).
    #[must_use]
    pub(crate) fn new(
        requester: &'a Requester,
        trace_id: TraceId,
        attribution_chain: &'a AttributionChain,
    ) -> Self {
        PredicateContext {
            requester,
            trace_id,
            attribution_chain,
            _no_oracles: PhantomData,
            _no_sinks: PhantomData,
            _private: PhantomData,
        }
    }

    /// Borrow the requester identity.
    #[must_use]
    pub fn requester(&self) -> &Requester {
        self.requester
    }

    /// Return the forensic trace id.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Borrow the attribution chain.
    #[must_use]
    pub fn attribution_chain(&self) -> &AttributionChain {
        self.attribution_chain
    }
}

/// Per-capability issuance-policy trait (§4.3).
///
/// The `capability_predicate` runs at stage 5 of the §4.3
/// pipeline after the block / audience / mute oracle
/// consultations have already executed and their results are
/// presented as the typed [`UserCapability::OracleResults`].
///
/// `required_jwt_scope` (§7.2) declares the optional JWT scope
/// string an operator-issued token must include for the
/// issuance chokepoint to admit this capability. The default
/// implementation returns `None` — v0.1's v1 capabilities
/// inherit the no-scope-required default. Operators wiring
/// per-capability scope policies override it; mismatch produces
/// [`crate::AuthDenial::ScopeMismatch`] which the bind path
/// surfaces as
/// [`BindOutcomeRepr::DeniedAtPipeline`]`{ stage:
/// PipelineStage::JwtScope, reason:
/// DenialReason::JwtScopeInsufficient }`.
pub trait IssuancePolicy: UserCapability {
    /// Apply the capability-specific check.
    fn capability_predicate(
        ctx: &PredicateContext<'_>,
        target: &<Self as UserCapability>::Subject,
        oracle_results: &<Self as UserCapability>::OracleResults,
    ) -> Result<(), DenialReason>;

    /// Optional JWT-scope requirement (§7.2). `None` means the
    /// JWT-scope check is bypassed; `Some(s)` means the
    /// capability is issued only when the verified JWT's
    /// `JwtScope::scopes` contains `s`.
    ///
    /// The crate ships no scope vocabulary; operators define
    /// their own scope strings (typically NSID-shaped, e.g.,
    /// `"com.atproto.repo.createRecord"` or
    /// `"tools.kryphocron.admin.takedown"`).
    fn required_jwt_scope() -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_error_includes_attribution_receipt_invalid() {
        // §4.3 round-5 patch: AttributionReceiptInvalid must be a
        // variant of BindError. Pin it so future refactors don't
        // silently remove it.
        let _e = BindError::AttributionReceiptInvalid {
            failing_hop: 0,
            reason: ReceiptVerificationFailure::Malformed,
        };
    }

    #[test]
    fn pipeline_stage_carries_jwt_scope_per_7_2() {
        // §7.2 extends PipelineStage with JwtScope. Pin the variant
        // so the extension is part of v0.1's surface.
        let _s = PipelineStage::JwtScope;
    }

    /// §4.3 stage 1: `RequesterLacksAuthority` carries the
    /// capability class and the requester kind found. Pin the
    /// variant shape so future refactors don't silently drop a
    /// forensic-correlation field.
    #[test]
    fn requester_lacks_authority_carries_class_and_found_kind() {
        let e = AuthDenial::RequesterLacksAuthority {
            class: CapabilityClass::Substrate,
            found: RequesterKind::Anonymous,
        };
        match e {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::Substrate);
                assert_eq!(found, RequesterKind::Anonymous);
            }
            other => panic!("expected RequesterLacksAuthority, got {other:?}"),
        }
    }

    /// §4.3 stage 0: `DenialReason::CapabilityDeprecated`
    /// carries nsid + since_version + successor. Pin the variant
    /// shape so future refactors don't silently drop forensic
    /// detail.
    #[test]
    fn capability_deprecated_carries_nsid_version_and_successor() {
        let r = DenialReason::CapabilityDeprecated {
            nsid: "tools.kryphocron.feed.postOld",
            since_version: SemVer::new(1, 0, 0),
            successor: Some("tools.kryphocron.feed.postPrivate"),
        };
        match r {
            DenialReason::CapabilityDeprecated {
                nsid,
                since_version,
                successor,
            } => {
                assert_eq!(nsid, "tools.kryphocron.feed.postOld");
                assert_eq!(since_version, SemVer::new(1, 0, 0));
                assert_eq!(successor, Some("tools.kryphocron.feed.postPrivate"));
            }
            other => panic!("expected CapabilityDeprecated, got {other:?}"),
        }
    }

    /// §4.3: `BindError::DeniedAtPipeline { stage, reason }`
    /// mirrors `BindOutcomeRepr::DeniedAtPipeline`. Pin
    /// constructibility so the bind path's primary denial channel
    /// is part of the v0.1 surface.
    #[test]
    fn bind_error_denied_at_pipeline_constructible() {
        let e = BindError::DeniedAtPipeline {
            stage: PipelineStage::DeprecationGate,
            reason: DenialReason::CapabilityDeprecated {
                nsid: "tools.kryphocron.feed.postOld",
                since_version: SemVer::new(1, 0, 0),
                successor: None,
            },
        };
        match e {
            BindError::DeniedAtPipeline { stage, reason } => {
                assert_eq!(stage, PipelineStage::DeprecationGate);
                assert!(matches!(reason, DenialReason::CapabilityDeprecated { .. }));
            }
            other => panic!("expected DeniedAtPipeline, got {other:?}"),
        }
    }
}

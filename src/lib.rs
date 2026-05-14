//! # kryphocron — primitives crate
//!
//! The vocabulary the kryphocron substrate uses to express its
//! threat-model commitments in Rust types.
//!
//! This crate provides:
//!
//! - Tier-aware envelope types ([`Tier`], [`Tiered`]) and the
//!   [`HasNsid`] trait family connecting lexicons to tier
//!   classification (§4.1, §4.4).
//! - [`AuthContext`], the in-process authentication context type,
//!   and the [`ingress`] submodule that constructs it from verified
//!   evidence (§4.2).
//! - Capability proof types and the [`authority`] module that
//!   issues them, with sealed traits and [`PhantomData`]-token
//!   patterns making proofs unforgeable in safe code (§4.3, §4.7).
//! - [`TargetRepresentation`] split into structural and sensitive
//!   layers; routine operator audit reads structural, forensic
//!   detail requires the segregated decryption key (§4.4).
//! - [`oracle`] traits — [`oracle::BlockOracle`],
//!   [`oracle::AudienceOracle`], [`oracle::MuteOracle`] — with
//!   freshness commitments and per-query worst-case latency
//!   reporting (§4.5).
//! - Timing equalization helpers and the non-enumeration discipline
//!   (§4.6).
//! - Wire-format types for cross-service capability claims and
//!   the per-entry delegation receipt machinery that makes
//!   attribution chains tamper-evident across hops (§4.8).
//! - [`audit`] pipeline traits, sink types, composite-audit
//!   rollback machinery, and the [`audit::FallbackAuditSink`]
//!   contract (§4.9).
//! - [`verification`] submodule shapes — [`verification::VerifiedJwt`],
//!   [`verification::VerifiedHandshake`] — that ingress depends on
//!   (§7.2, §7.5; surface only in Phase 1).
//! - [`resolver`] trait surfaces for DID resolution and federation-
//!   peer trust (§7.3, §7.7; surface only in Phase 1).
//! - [`encryption`] hook-trait surfaces and opaque key-id types
//!   (§8.2, §8.3; surface only in Phase 1 — no v1 implementation).
//!
//! ## Discipline
//!
//! - The wrong path is harder to write than the right path. Misuse
//!   of a primitive is a compile error wherever possible, a runtime
//!   error otherwise, and a silent success never.
//! - Capabilities are unforgeable in safe code. Code outside the
//!   crate's [`authority`] module cannot construct authorization
//!   proofs in safe Rust. The crate enforces this with sealed
//!   traits and a private token type carried in
//!   [`PhantomData`] on every proof type. Unforgeability in the
//!   presence of `unsafe` is a policy claim enforced by
//!   `#![forbid(unsafe_code)]` across substrate-compliant
//!   consumers; this crate itself forbids `unsafe` at the lints
//!   level.
//! - Tier is not a label, it's a structural property. A function
//!   that emits to a public surface cannot accept a private-tier
//!   value, by type, not by runtime check.
//! - Audit reflects action, not intent. Audit events fire on the
//!   *binding* of a capability proof (success or failure), not on
//!   its issuance.
//!
//! ## Phase 1 status
//!
//! This crate's v0.1.0 (phase-1) release implements the §4 type
//! architecture committed by the design doc. Runtime logic for
//! capability binding, oracle consultations, JWT/handshake
//! verification, and audit-sink dispatch is **stubbed**:
//! the trait surfaces and type shapes are real and load-bearing
//! for downstream compile-time invariant enforcement, but calling
//! a stubbed function panics with [`todo!`] or
//! [`unimplemented!`]. Phase 4 (§7 wire-format implementation)
//! and Phase 5 (§8 encryption hooks) fill in the runtime logic.
//!
//! [`PhantomData`]: core::marker::PhantomData

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc(html_no_source)]
// Phase 1 ships the type architecture with stubbed runtime logic
// (§4.10 pipeline implementation lives in Phase 4). Many
// crate-internal constructors and fields are referenced only by
// Phase-4 callers that haven't landed yet; the `dead_code` warning
// is the natural consequence and not load-bearing here. CHAINLINKS
// #11 tracks reverting this allow once Phase 4 wires the pipeline.
#![allow(dead_code)]

// Internal modules.
mod sealed;
mod proto;
mod identity;

// Public modules per §9.1.

/// §4.3 capability proof issuance, sealed trait machinery, and
/// the v1 capability vocabulary.
pub mod authority;

/// §4.9 audit pipeline traits, sink types, composite-audit
/// rollback machinery, fallback sink contract.
pub mod audit;

/// §8 encryption-hook surfaces. v1 ships only the type vocabulary
/// and the trait shapes; no implementations.
pub mod encryption;

/// §4.2 ingress submodule — constructs [`AuthContext`] values from
/// verified evidence types produced by [`verification`].
pub mod ingress;

/// §4.5 oracle traits: block, audience, mute. Freshness
/// commitments and per-query worst-case latency reporting.
pub mod oracle;

/// §7.3, §7.7 DID resolution and federation-peer trust trait
/// surfaces. Phase 1 ships shapes only; concrete resolvers are
/// operator territory.
pub mod resolver;

/// §4.1, §4.4 tier model and tier-aware envelope types.
pub mod tier;

/// §7.2 JWT / handshake / claim verification. The only path that
/// produces [`verification::VerifiedJwt`] and
/// [`verification::VerifiedHandshake`] values; downstream code
/// that takes one of those types knows verification ran.
pub mod verification;

// Phase-1 internal areas that span §4 but don't carry their own
// committed public module path in §9.1. We expose them at the
// crate root to keep the public-surface lookup short.
mod non_enumeration;
mod target;
mod timing;
mod wire;

// Crate-root re-exports of the load-bearing public types.

pub use audit::{
    AuditError, ChannelAuditSink, FallbackAuditSink, ModerationAuditSink, SinkKind,
    SinkPanicGuard, SubstrateAuditSink, TerminatedSinkGuard, UserAuditSink,
};
pub use authority::{
    AuthDenial, AuthorityId, BindError, BindFailureReason, BindOutcomeRepr,
    BoundChannelProof, BoundModerationProof, BoundSubstrateProof, BoundUserProof,
    CapabilityClass, CapabilityKind, CapabilitySemantics, CapabilitySet, ChannelProof,
    ChannelProofRef, DenialReason, Endpoint, InspectionKind, InspectionNotification,
    InspectionNotificationQueueReader, IssuancePolicy, ModerationCapability,
    ModerationProof, ModerationProofRef, NotificationId, PipelineStage, PredicateContext,
    ResourceId, SubstrateProof, SubstrateProofRef, SubstrateScope, UserCapability,
    UserProof, UserProofRef,
};
pub use encryption::{
    AuditEncryptionAlgorithm, AuditEncryptionKeyId, EncryptionError,
    RecordEncryptionAlgorithm, RecordEncryptionKeyId,
};
pub use identity::{
    CorrelationKey, KeyId, PublicKey, RotationChain, RotationEntry,
    ServiceIdentity, SessionDigest, SessionId, SignatureAlgorithm,
    TraceId,
};
pub use ingress::{
    AttributionChain, AttributionEntry, AuthContext, AuditSinks,
    DerivationReason, DeriveError, Narrowing, OracleSet, Requester,
    MAX_CHAIN_DEPTH,
};
pub use non_enumeration::Outcome;
pub use oracle::{
    AudienceOracleQuery, AudienceState, BlockOracleQuery, BlockState,
    MuteOracleQuery, MuteState, OracleKind, OracleQueryKind,
};
pub use proto::{AtUri, BlobRef, Cid, CidError, Datetime, Did, Handle, Nsid, RecordKey, Rkey, Tid, UnknownNsid};

// Phase 2 re-exports from the lexicon companion crate (§5.3 /
// §5.4 / §5.6). The lexicon set's compiled-in registry is the
// substrate's runtime trust anchor for tier classification and
// deprecation state.
pub use kryphocron_lexicons::{
    DeprecationState, LexiconRegistryEntry, KRYPHOCRON_CODEGEN_HASH,
    KRYPHOCRON_LEXICON_REGISTRY,
};
pub use target::{
    ScopeKind, SensitiveRepresentation, StructuralRepresentation,
    TargetRepresentation,
};
pub use tier::{
    visible_to, HasNsid, MixedTier, PrivateTier, PublicTier, Tier,
    TierWitness, Tiered, Visibility,
};
pub use timing::{
    equalize_timing, equalize_timing_target_for,
    BASE_AUTHORIZATION_OVERHEAD, SAFETY_MARGIN,
};
pub use wire::{
    AttributionChainWire, AttributionEntryWire, AttributionPrincipal,
    CapabilityClaim, ClaimConstructionError, ClaimNonce, ClaimOrigin,
    ClaimSignature, DelegationReceipt, DelegationReceiptPayload,
    JwtNonce, NonceFreshness, NonceIssuerKey, NonceKind,
    NoncePrincipal, NonceTracker, NonceTrackerError,
    ReceiptVerificationFailure, ResourceScope, ScopeVariantName,
    MAX_CLAIM_VALIDITY, MAX_ROTATION_DEPTH,
};

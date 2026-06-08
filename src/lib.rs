// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # kryphocron — primitives crate
//!
//! The vocabulary the kryphocron substrate uses to express its
//! threat-model commitments in Rust types.
//!
//! v0.1.0 ships the substrate's authority discipline end-to-end:
//! issuance, bind, reborrow, context derivation, tier-aware
//! visibility, audit emission with composite-rollback semantics,
//! timing-channel equalization, JWT and capability-claim
//! verification, the three-message sync-handshake protocol, and
//! the encryption-hook trait surfaces.
//!
//! This crate provides:
//!
//! - Tier-aware envelope types ([`Tier`], [`Tiered`]) and the
//!   [`HasNsid`] trait family connecting lexicons to tier
//!   classification (§4.1, §4.4). [`tier::visible_to`] is the
//!   tier × requester-class read predicate.
//! - [`AuthContext`], the in-process authentication context type,
//!   the [`ingress`] submodule that constructs it from verified
//!   evidence, and [`AuthContext::derive_for`] for scope-narrowing
//!   sub-context derivation across three legal narrowings
//!   (drop-to-anonymous, narrow-capabilities,
//!   service-to-service) (§4.2).
//! - Capability proof types and the [`authority`] module that
//!   issues them via [`authority::issue_user`] /
//!   [`authority::issue_channel`] /
//!   [`authority::issue_substrate`] /
//!   [`authority::issue_moderation`]. Each issued proof exposes
//!   `bind` and `reborrow` async methods running the §4.3
//!   pipeline (pre-checks → stage-0 deprecation gate →
//!   stage-2 oracle consultation, user-class only →
//!   stage-5 predicate → audit emit → stage-6 timing
//!   equalization → return). Proofs are unforgeable in safe
//!   code via sealed traits and [`PhantomData`]-token patterns
//!   (§4.3, §4.7).
//! - [`TargetRepresentation`] split into structural and sensitive
//!   layers; routine operator audit reads structural, forensic
//!   detail requires the segregated decryption key (§4.4).
//! - [`oracle`] traits — [`oracle::BlockOracle`],
//!   [`oracle::AudienceOracle`], [`oracle::MuteOracle`] — with
//!   freshness commitments and per-query worst-case latency
//!   reporting consumed by [`equalize_timing_target_for`] (§4.5).
//! - [`equalize_timing`] for closing the §4.6 timing-channel gap
//!   at the bind path's stage 6.
//! - Wire-format types for cross-service capability claims and
//!   the per-entry delegation receipt machinery that makes
//!   attribution chains tamper-evident across hops (§4.8).
//! - [`audit`] pipeline: per-class sink traits, the §4.9
//!   composite-audit machinery ([`audit::composite_audit`])
//!   with class-priority commit order, rollback fan-out, and
//!   the [`audit::FallbackAuditSink`] escalation contract; a
//!   30+ variant audit-event vocabulary; the §6.7 inspection-
//!   notification queue trait ([`authority::InspectionNotificationQueueImpl`])
//!   for moderation-class fan-out.
//! - [`verification`] submodule — [`verification::VerifiedJwt`],
//!   [`verification::VerifiedCapabilityClaim`],
//!   [`verification::VerifiedSyncMessage`], and the three-message
//!   sync-handshake evidence types
//!   ([`verification::VerifiedSyncHello`],
//!   [`verification::VerifiedSyncAccept`],
//!   [`verification::VerifiedSyncEstablished`]) — the only path
//!   that produces verified evidence the [`ingress`] submodule
//!   accepts (§7.2, §7.5).
//! - [`trust`] service-trust-declaration verification (§7.4).
//! - [`resolver`] trait surfaces for DID resolution and federation-
//!   peer trust (§7.3, §7.7).
//! - [`encryption`] hook-trait surfaces and opaque key-id types
//!   (§8.2, §8.3; trait surface only — v0.1 ships [`encryption::NoEncryption`]
//!   as the default no-op resolver set, operator plug-ins fill
//!   in real algorithm support).
//!
//! ## Discipline
//!
//! - **The wrong path is harder to write than the right path.**
//!   Misuse of a primitive is a compile error wherever possible,
//!   a runtime error otherwise, and a silent success never.
//! - **Capabilities are unforgeable in safe code.** Code outside
//!   the crate's [`authority`] module cannot construct
//!   authorization proofs in safe Rust. Sealed traits and a
//!   private token type carried in [`PhantomData`] on every
//!   proof type enforce this. The crate forbids `unsafe` at the
//!   lints level.
//! - **Tier is not a label, it's a structural property.** A
//!   function that emits to a public surface cannot accept a
//!   private-tier value, by type, not by runtime check.
//! - **Audit reflects action, not intent.** Audit events fire
//!   on the *binding* of a capability proof (success or
//!   failure), not on its issuance.
//! - **Door-open, not door-ajar.** Where the spec defers to
//!   operator policy (encryption algorithm, oracle backends,
//!   audit sink storage, inspection-notification queue), the
//!   crate ships a trait surface + explicit no-op default
//!   ([`encryption::NoEncryption`],
//!   [`authority::NoInspectionNotifications`]); operators
//!   install real implementations when their deployment needs
//!   them.
//!
//! ## v0.1 enrichment posture
//!
//! The audit pipeline is wired end-to-end. Certain audit-event
//! payload fields ship with placeholder data in v0.1 pending
//! per-class sealed-extraction traits in v0.2 (channel-class
//! peer + session id; substrate-class scope kind; moderation-
//! class case id); user-class oracle consultations consult only
//! the universal block-vs-resource-owner query in v0.1
//! (multi-query consultations land alongside a per-capability
//! oracle-results-builder in v0.2). The
//! [`AuthContext::derive_for`] [`ingress::NarrowCapabilities`]
//! narrowing ships recording-only — the [`AuthContext`] gains a
//! capabilities field in v0.2 for structural superset
//! enforcement. [`tier::visible_to`] is tier-only in v0.1; an
//! audience-aware overload lands in v0.2.
//!
//! [`PhantomData`]: core::marker::PhantomData

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc(html_no_source)]
// Dead-code lints are addressed per-item with targeted
// `#[allow]` annotations where the type/function is part of the
// public surface but not consumed by the crate itself yet
// (operator-pluggable trait surfaces, future-accessor scaffolding).

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
/// surfaces. The crate ships trait shapes; concrete resolvers are
/// operator territory.
pub mod resolver;

/// §7.4 service-trust-declaration verification.
///
/// Trust declarations are minted by operator tooling (typically a
/// CLI signing with a hardware-token-held trust-root key). The
/// crate provides the verification path; construction is operator-
/// managed.
pub mod trust;

/// §4.1, §4.4 tier model and tier-aware envelope types.
pub mod tier;

/// §7.2 JWT / handshake / claim verification. The only path that
/// produces [`verification::VerifiedJwt`],
/// [`verification::VerifiedCapabilityClaim`],
/// [`verification::VerifiedSyncMessage`], and the three-message
/// sync-handshake evidence values; downstream code that takes one
/// of those types knows verification ran.
pub mod verification;

// Internal areas that span §4 but don't carry their own
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
    check_jwt_scope_for, AuthDenial, AuthorityId, BindError, BindFailureReason,
    BindOutcomeRepr, BoundChannelProof, BoundModerationProof, BoundSubstrateProof,
    BoundUserProof, CapabilityClass, CapabilityKind, CapabilitySemantics, CapabilitySet,
    ChannelProof, ChannelProofRef, DenialReason, Endpoint, HasResourceLocation,
    InspectionKind, InspectionNotification, InspectionNotificationQueueImpl,
    InspectionNotificationQueueReader, IssuancePolicy, ModerationCapability,
    ModerationProof, ModerationProofRef, NoInspectionNotifications, NotificationId,
    PipelineStage, PredicateContext, ResourceId, SubstrateProof, SubstrateProofRef,
    SubstrateScope, UserCapability, UserProof, UserProofRef,
};
pub use encryption::{
    produce_sensitive_representation, AuditEncryptionAlgorithm,
    AuditEncryptionKeyId, AuditEncryptionResolver, EncryptedRecord,
    EncryptionContext, EncryptionError, EncryptionResolverSet, NoEncryption,
    RecordEncryptionAlgorithm, RecordEncryptionContext,
    RecordEncryptionKeyId, RecordEncryptionResolver,
};
pub use identity::{
    CorrelationKey, KeyId, PublicKey, RotationChain, RotationEntry,
    ServiceIdentity, SessionDigest, SessionId, SignatureAlgorithm,
    SubstrateSessionDerivationKey, TraceId,
};
pub use ingress::{
    AttributionChain, AttributionEntry, AuthContext, AuditSinks,
    DerivationReason, DeriveError, Narrowing, OracleSet, Requester, RequesterKind,
    MAX_CHAIN_DEPTH,
};
pub use non_enumeration::Outcome;
pub use oracle::{
    AudienceOracleQuery, AudienceState, BlockOracleQuery, BlockState,
    MuteOracleQuery, MuteState, OracleKind, OracleQueryKind,
};
pub use proto::{AtUri, BlobRef, Cid, CidError, Datetime, Did, Handle, Nsid, RecordKey, Rkey, Tid, UnknownNsid};

// §5.3 / §5.4 / §5.6 re-exports from the lexicon companion crate.
// The lexicon set's compiled-in registry is the substrate's
// runtime trust anchor for tier classification and deprecation
// state.
pub use kryphocron_lexicons::{
    lexicons, DeprecationState, LexiconRegistryEntry, KRYPHOCRON_CODEGEN_HASH,
    KRYPHOCRON_LEXICON_REGISTRY,
};
pub use target::{
    ScopeKind, SensitiveRepresentation, StructuralRepresentation,
    TargetRepresentation,
};
pub use tier::{
    visible_to, HasNsid, MixedTier, PrivateTier, PublicTier, Tier,
    TierWitness, Tiered, Visibility, KRYPHOCRON_IMPLEMENTED_NSIDS,
};
pub use timing::{
    equalize_timing, equalize_timing_target_for,
    BASE_AUTHORIZATION_OVERHEAD, SAFETY_MARGIN,
};
pub use wire::{
    accept_sign_input, derive_session_id, established_sign_input, hello_sign_input,
    reject_sign_input, sign_delegation_receipt, sign_handshake_payload,
    verify_handshake_signature, AttributionChainWire, AttributionEntryWire,
    AttributionPrincipal, CapabilityClaim, ClaimConstructionError, ClaimNonce,
    ClaimOrigin, ClaimSignature, DefaultHandshakeNonceTracker,
    DefaultNonceTracker, DelegationReceipt, DelegationReceiptPayload,
    HandshakeNonceTracker, JwtNonce, NonceFreshness, NonceIssuerKey, NonceKind,
    NoncePrincipal, NonceTracker, NonceTrackerError, ReceiptVerificationFailure,
    ResourceScope, ScopeVariantName, SessionNonce, SyncChannelAccept,
    SyncChannelEstablished, SyncChannelHello, SyncChannelReject,
    SyncChannelResponse, SyncDirection, SyncRequestedScope, SyncTimeWindow,
    ACCEPT_DOMAIN_TAG, DEFAULT_FEDERATION_TIME_WINDOW, DEFAULT_NONCE_RETENTION,
    DEFAULT_PER_PARTITION_CAP, ESTABLISHED_DOMAIN_TAG, HELLO_DOMAIN_TAG,
    MAX_CAPABILITY_CLAIM_SIZE, MAX_CLAIM_VALIDITY,
    MAX_HANDSHAKE_MESSAGE_SIZE, MAX_HANDSHAKE_NONCE_REPLAY_WINDOW,
    MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES, MAX_ROTATION_DEPTH, REJECT_DOMAIN_TAG,
};

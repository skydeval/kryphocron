//! §4.2 ingress submodule and the [`AuthContext`] type.
//!
//! [`AuthContext`] is the in-process authentication context the
//! substrate carries through every authorization decision. It is
//! constructed only via the `ingress` submodule functions
//! (`from_xrpc_request`, `from_sync_channel_handshake`,
//! `anonymous_for_public_read`), each of which accepts a
//! verified-evidence type. Code outside the crate cannot construct
//! an [`AuthContext`] via struct-literal syntax because every
//! field is private and the type carries a `PhantomData<*const ()>`
//! to forbid `Clone`.
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
use crate::audit::{
    ChannelAuditSink, FallbackAuditSink, ModerationAuditSink, SubstrateAuditSink,
    UserAuditSink,
};
use crate::identity::{ServiceIdentity, TraceId};
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
    _no_clone: PhantomData<*const ()>,
}

// Manually implement Send + Sync — the *const () makes AuthContext
// !Send + !Sync by default. The contained references are Send+Sync,
// so we restore them explicitly. The *const () is purely for !Clone.
//
// Safety: all fields are themselves Send + Sync; the *const ()
// marker carries no data and is purely a trait-impl signal.
//
// Phase 1 ships this without unsafe; the crate forbids unsafe
// globally. Phase 4 will revisit if performance auditing requires
// it, but the type itself does not need Send/Sync for Phase 1's
// scope — the AuthContext is process-local and used inside a
// single bind path. See CHAINLINKS #7.

impl<'a> AuthContext<'a> {
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
    /// [`ServiceToService`]. `Did → Service` is runtime-rejected
    /// per §4.2 (`UndeclaredServiceTrust` if attempted via
    /// [`ServiceToService`] without a trust declaration).
    ///
    /// Sub-contexts inherit [`TraceId`] and extend
    /// [`AttributionChain`]. Failures audit.
    ///
    /// **Phase 1 stub.** Phase 4 wires the chain-extension and
    /// audit-emit logic.
    ///
    /// # Errors
    ///
    /// See [`DeriveError`].
    pub fn derive_for<N: Narrowing>(
        &self,
        _narrowing: N,
    ) -> Result<AuthContext<'_>, DeriveError> {
        unimplemented!(
            "§4.2 AuthContext::derive_for: Phase 4 wires chain-extension + audit emit"
        );
    }
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
/// **Phase 1 stub.** Phase 4 wires the chain-rehydration logic
/// and the JWT-scope plumb-through.
#[must_use]
pub fn from_xrpc_request<'a>(
    _evidence: crate::verification::VerifiedJwt,
    _trace_id: TraceId,
    _sinks: AuditSinks<'a>,
    _oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    unimplemented!(
        "§4.2 ingress::from_xrpc_request: Phase 4 wires AuthContext rehydration"
    );
}

/// Construct [`AuthContext`] from a verified service-issued
/// capability claim (§7.6).
///
/// Parallel to [`from_xrpc_request`] but for the
/// substrate-internal trust context: the resulting context's
/// [`Requester`] variant is [`Requester::Service`] carrying the
/// claim's issuer identity.
///
/// **Phase 4b stub.** The constructor signature ships with the
/// `VerifiedCapabilityClaim` type from §7.6 wired, but
/// `AuthContext` construction still requires the same
/// chain-rehydration / sink-plumbing wiring [`from_xrpc_request`]
/// is awaiting (Phase 4d / 4e). Both stubs land together when
/// the broader `AuthContext` construction path crystalizes.
#[must_use]
pub fn from_service_request<'a>(
    _evidence: crate::verification::VerifiedCapabilityClaim,
    _trace_id: TraceId,
    _sinks: AuditSinks<'a>,
    _oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    unimplemented!(
        "§7.6 ingress::from_service_request: Phase 4d/4e wires AuthContext rehydration"
    );
}

/// Construct [`AuthContext`] from a verified sync-channel
/// handshake (§4.2).
///
/// **Phase 1 stub.** Phase 4 wires.
#[must_use]
pub fn from_sync_channel_handshake<'a>(
    _evidence: crate::verification::VerifiedHandshake,
    _trace_id: TraceId,
    _sinks: AuditSinks<'a>,
    _oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    unimplemented!("§4.2 ingress::from_sync_channel_handshake: Phase 4 wires");
}

/// Construct [`AuthContext`] from a verified post-handshake
/// sync-channel message (§7.5 / §7.6).
///
/// **Phase 4b stub.** The signature ships with the
/// [`crate::verification::VerifiedSyncMessage`] type from §7.6
/// wired; construction requires the sync handshake
/// implementation that lands in Phase 4d.
#[must_use]
pub fn from_sync_channel_message<'a>(
    _evidence: crate::verification::VerifiedSyncMessage,
    _trace_id: TraceId,
    _sinks: AuditSinks<'a>,
    _oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    unimplemented!(
        "§7.5 ingress::from_sync_channel_message: Phase 4d wires the handshake-evidence path"
    );
}

/// Construct an anonymous [`AuthContext`] for public-read paths
/// (§4.2).
///
/// **Phase 1 stub.** Phase 4 wires.
#[must_use]
pub fn anonymous_for_public_read<'a>(
    _sinks: AuditSinks<'a>,
    _oracles: OracleSet<'a>,
) -> AuthContext<'a> {
    unimplemented!("§4.2 ingress::anonymous_for_public_read: Phase 4 wires");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_chain_depth_pinned_at_8() {
        // §4.2 commits MAX_CHAIN_DEPTH = 8.
        assert_eq!(MAX_CHAIN_DEPTH, 8);
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
}

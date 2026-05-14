//! §4.8 `CapabilityClaim` — the cross-service wire vocabulary.

use core::marker::PhantomData;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::authority::capability::CapabilityKind;
use crate::authority::subjects::ResourceId;
use crate::identity::{ServiceIdentity, TraceId};
use crate::proto::Did;
use crate::sealed;

use super::nonce::ClaimNonce;
use super::receipt::AttributionChainWire;
use super::signature::ClaimSignature;

/// Maximum validity window for a [`CapabilityClaim`] (§4.8).
pub const MAX_CLAIM_VALIDITY: Duration = Duration::from_secs(600);

/// Cross-service wire vocabulary for capability delegation (§4.8).
///
/// `CapabilityClaim` is the **only** vocabulary for cross-service
/// trust (§4.8 W1). All fields are private; construction goes
/// through [`CapabilityClaim::new`] which validates per-class
/// scope, validity bounds, and signs. Deserialization runs the
/// same validation (defense in depth).
///
/// **Phase 1 ships the type shape.** The deterministic-CBOR
/// canonicalization and Ed25519 signing implementation fires in
/// Phase 4.
#[derive(Debug, Clone)]
pub struct CapabilityClaim {
    issuer: ServiceIdentity,
    audience: ServiceIdentity,
    subject: Did,
    origin: ClaimOrigin,
    capabilities: Vec<CapabilityKind>,
    resource_scope: ResourceScope,
    nonce: ClaimNonce,
    trace_id: TraceId,
    issued_at: SystemTime,
    expires_at: SystemTime,
    signature: ClaimSignature,
    _private: PhantomData<sealed::Token>,
}

impl CapabilityClaim {
    /// Construct a [`CapabilityClaim`] (§4.8 constructor).
    ///
    /// Validation per-class:
    ///
    /// - Substrate-class and moderation-class capabilities are
    ///   never wire-eligible (§4.8 W6); attempting either rejects
    ///   with [`ClaimConstructionError::NonWireEligibleCapability`].
    /// - User-class restricts `resource_scope` to
    ///   [`ResourceScope::Resource`] (§4.8 W9).
    /// - Mixed-class claims must satisfy **all** classes' scope
    ///   restrictions (§4.8 W10).
    /// - `validity` must be ≤ [`MAX_CLAIM_VALIDITY`].
    /// - Phase 4 wires the signing path; Phase 1 returns
    ///   [`ClaimConstructionError::SigningFailed`].
    ///
    /// # Errors
    ///
    /// See [`ClaimConstructionError`].
    pub fn new(
        _issuer: ServiceIdentity,
        _audience: ServiceIdentity,
        _subject: Did,
        capabilities: Vec<CapabilityKind>,
        resource_scope: ResourceScope,
        _nonce: ClaimNonce,
        _trace_id: TraceId,
        validity: Duration,
    ) -> Result<Self, ClaimConstructionError> {
        // §4.8 validity ceiling.
        if validity > MAX_CLAIM_VALIDITY {
            return Err(ClaimConstructionError::ValidityTooLong {
                requested: validity,
                max: MAX_CLAIM_VALIDITY,
            });
        }

        // §4.8 W6: substrate / moderation capabilities never on
        // the wire.
        for cap in &capabilities {
            if !cap.is_wire_eligible() {
                return Err(ClaimConstructionError::NonWireEligibleCapability(*cap));
            }
        }

        // §4.8 W9 / W10: per-class scope restrictions. The
        // validate-per-class logic is straightforward but the
        // crate-level enforcement matters; Phase 4 expands this
        // with the Channel-class permitted broader scopes.
        for cap in &capabilities {
            check_scope_for_class(*cap, &resource_scope)?;
        }

        // Phase 4 wires the signing path.
        Err(ClaimConstructionError::SigningFailed)
    }

    /// Borrow the issuer.
    #[must_use]
    pub fn issuer(&self) -> &ServiceIdentity {
        &self.issuer
    }

    /// Borrow the audience (W2).
    #[must_use]
    pub fn audience(&self) -> &ServiceIdentity {
        &self.audience
    }

    /// Borrow the subject DID.
    #[must_use]
    pub fn subject(&self) -> &Did {
        &self.subject
    }

    /// Borrow the claim origin (W11).
    #[must_use]
    pub fn origin(&self) -> &ClaimOrigin {
        &self.origin
    }

    /// Borrow the requested capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityKind] {
        &self.capabilities
    }

    /// Borrow the resource scope.
    #[must_use]
    pub fn resource_scope(&self) -> &ResourceScope {
        &self.resource_scope
    }

    /// Borrow the nonce.
    #[must_use]
    pub fn nonce(&self) -> &ClaimNonce {
        &self.nonce
    }

    /// Return the trace id.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Return `issued_at`.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// Return `expires_at`.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Borrow the signature.
    #[must_use]
    pub fn signature(&self) -> &ClaimSignature {
        &self.signature
    }
}

fn check_scope_for_class(
    cap: CapabilityKind,
    scope: &ResourceScope,
) -> Result<(), ClaimConstructionError> {
    use crate::authority::capability::CapabilityClass;

    // §4.8: substrate/moderation forbidden — already caught by
    // is_wire_eligible above; defense in depth here.
    match cap.class() {
        CapabilityClass::User => match scope {
            ResourceScope::Resource(_) => Ok(()),
            other => Err(ClaimConstructionError::ScopeNotPermittedForClass {
                capability: cap,
                scope_variant: ScopeVariantName::from(other),
            }),
        },
        CapabilityClass::Channel => match scope {
            ResourceScope::Resource(_)
            | ResourceScope::AllResourcesOwnedBy(_)
            | ResourceScope::ClassWideAdministrative => Ok(()),
        },
        CapabilityClass::Substrate | CapabilityClass::Moderation => {
            Err(ClaimConstructionError::NonWireEligibleCapability(cap))
        }
    }
}

/// Origin discriminator for a [`CapabilityClaim`] (§4.8 W11).
///
/// Disambiguates self-originated from delegated-from-upstream
/// claims so receiving substrate components reconstruct
/// [`crate::AttributionChain`] deterministically.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOrigin {
    /// Issuer is acting on its own behalf. `subject` is the
    /// issuer's own service-bound DID; the resulting chain has
    /// a single entry.
    SelfOriginated,
    /// Issuer is acting on behalf of an upstream principal.
    /// `subject` is the upstream principal's DID; the chain
    /// carries the full delegation path with per-entry
    /// [`crate::wire::DelegationReceipt`]s attesting each hop
    /// (§4.8 W11 / W12 / W13).
    DelegatedFromUpstream {
        /// The full attribution-chain wire representation.
        chain: AttributionChainWire,
    },
}

/// Per-class resource scope (§4.8).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceScope {
    /// Scope to a specific resource. Required for user-class
    /// capabilities (W9).
    Resource(ResourceId),
    /// All resources owned by a DID. Channel-class only.
    AllResourcesOwnedBy(Did),
    /// Class-wide administrative scope. Channel-class only.
    ClassWideAdministrative,
}

/// Stable variant-name discriminator over [`ResourceScope`]
/// (§4.8). Used in error reporting.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeVariantName {
    /// [`ResourceScope::Resource`].
    Resource,
    /// [`ResourceScope::AllResourcesOwnedBy`].
    AllResourcesOwnedBy,
    /// [`ResourceScope::ClassWideAdministrative`].
    ClassWideAdministrative,
}

impl From<&ResourceScope> for ScopeVariantName {
    fn from(s: &ResourceScope) -> Self {
        match s {
            ResourceScope::Resource(_) => ScopeVariantName::Resource,
            ResourceScope::AllResourcesOwnedBy(_) => ScopeVariantName::AllResourcesOwnedBy,
            ResourceScope::ClassWideAdministrative => {
                ScopeVariantName::ClassWideAdministrative
            }
        }
    }
}

/// Failure cases at [`CapabilityClaim::new`] (§4.8).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClaimConstructionError {
    /// Capability is substrate-class or moderation-class
    /// (§4.8 W6).
    #[error("capability {0:?} is never wire-eligible")]
    NonWireEligibleCapability(CapabilityKind),
    /// Capability's class does not permit the supplied scope
    /// variant (§4.8 W9 / W10).
    #[error("capability {capability:?} does not permit scope variant {scope_variant:?}")]
    ScopeNotPermittedForClass {
        /// The offending capability.
        capability: CapabilityKind,
        /// The offending scope variant.
        scope_variant: ScopeVariantName,
    },
    /// Requested validity exceeds [`MAX_CLAIM_VALIDITY`].
    #[error("requested validity {requested:?} exceeds max {max:?}")]
    ValidityTooLong {
        /// Requested validity.
        requested: Duration,
        /// Maximum permitted.
        max: Duration,
    },
    /// Signing operation failed. Phase 4 fills in details; in
    /// Phase 1 this is the canonical "no signing implementation
    /// yet" error returned by [`CapabilityClaim::new`].
    #[error("signing failed")]
    SigningFailed,
    /// Operator-supplied rationale exceeded its byte budget.
    #[error("rationale length {len} exceeds max {max}")]
    RationaleTooLong {
        /// Actual length.
        len: usize,
        /// Maximum permitted.
        max: usize,
    },
    /// Claim serialization exceeded the per-§7.6 size ceiling
    /// (`MAX_CAPABILITY_CLAIM_SIZE`, committed in §7.6 and wired
    /// in Phase 4).
    #[error("claim size {size} exceeds max {max}")]
    ClaimTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum permitted.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_ceiling_pinned_at_600s() {
        // §4.8 commits MAX_CLAIM_VALIDITY = 600 seconds.
        assert_eq!(MAX_CLAIM_VALIDITY, Duration::from_secs(600));
    }

    #[test]
    fn scope_variant_name_round_trips() {
        let r = ResourceScope::ClassWideAdministrative;
        assert_eq!(
            ScopeVariantName::from(&r),
            ScopeVariantName::ClassWideAdministrative
        );
    }
}

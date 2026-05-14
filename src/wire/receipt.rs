//! §4.8 attribution-chain wire format + per-entry delegation
//! receipts (round-4 + round-5 patches).

use std::time::SystemTime;

use smallvec::SmallVec;
use thiserror::Error;

use crate::authority::capability::CapabilitySet;
use crate::identity::{KeyId, ServiceIdentity, SignatureAlgorithm};
use crate::ingress::{DerivationReason, MAX_CHAIN_DEPTH};
use crate::proto::Did;
use crate::resolver::DidResolutionError;

use super::signature::ClaimSignature;

/// Wire-side principal in an attribution chain (§4.8).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionPrincipal {
    /// User principal.
    User(Did),
    /// Service principal.
    Service(ServiceIdentity),
}

impl AttributionPrincipal {
    /// Return the principal's DID.
    #[must_use]
    pub fn did(&self) -> &Did {
        match self {
            AttributionPrincipal::User(d) => d,
            AttributionPrincipal::Service(s) => s.service_did(),
        }
    }

    /// Return the key id this principal used at delegation time.
    /// For `User`, key id is resolved via DID document at
    /// verification time and is not part of the structural
    /// principal; this method returns `None`.
    #[must_use]
    pub fn key_id(&self) -> Option<KeyId> {
        match self {
            AttributionPrincipal::User(_) => None,
            AttributionPrincipal::Service(s) => Some(s.key_id()),
        }
    }
}

/// Wire-serializable form of [`crate::AttributionChain`] (§4.8).
///
/// Per-entry [`DelegationReceipt`] makes the chain
/// **tamper-evident across hops**: a malicious intermediate
/// cannot fabricate the chain because it cannot produce a valid
/// receipt by a principal whose signing key it does not control
/// (§4.8 W11 round-5 patch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionChainWire {
    /// Originating principal — the upstream that initiated the
    /// delegation chain. Carries no receipt (it's the root). For
    /// user-initiated chains, the originating JWT serves as the
    /// implicit delegation authority (verified via DID resolution).
    pub origin: AttributionPrincipal,
    /// Subsequent delegation hops. `entries[i].receipt` is signed
    /// by the principal of `entries[i-1]` (or by `origin` for
    /// `i = 0`).
    pub entries: SmallVec<[AttributionEntryWire; MAX_CHAIN_DEPTH]>,
}

/// One delegation hop in an [`AttributionChainWire`] (§4.8).
///
/// Carries [`AttributionEntryWire::granted_capabilities`] per the
/// round-5 patch so the receiving substrate can enforce
/// cross-hop capability monotonicity (W13).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttributionEntryWire {
    /// The principal this entry represents — the service to
    /// which delegation was granted at this hop.
    pub principal: AttributionPrincipal,
    /// Why the previous principal narrowed / delegated.
    pub derivation_reason: DerivationReason,
    /// When the delegation happened.
    pub derived_at: SystemTime,
    /// Capabilities granted at this hop, after any narrowing.
    /// Must be a subset of the previous hop's granted capabilities
    /// (or, for hop 0, the origin's authorized set). §4.8 W13.
    pub granted_capabilities: CapabilitySet,
    /// Signature by the *previous* principal in the chain.
    pub receipt: DelegationReceipt,
}

/// Canonicalized payload covered by [`DelegationReceipt`] (§4.8
/// round-5 patch).
///
/// Principals canonicalized as `(did, key_id)` pairs (not full
/// [`ServiceIdentity`] values). This binds the receipt to the
/// specific signing key, enabling historical verification across
/// rotation: a chain signed under K1 verifies against K1's entry
/// in the principal's DID document rotation history, even if K1
/// is no longer current. Compromise of a current key cannot
/// forge receipts purporting to have been signed by a previous
/// key, because the previous key's `key_id` is named explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DelegationReceiptPayload {
    /// Previous principal's DID.
    pub previous_principal_did: Did,
    /// Previous principal's key id at delegation time.
    pub previous_key_id: KeyId,
    /// Recipient principal's DID.
    pub recipient_principal_did: Did,
    /// Recipient principal's key id at delegation time.
    pub recipient_key_id: KeyId,
    /// Reason for the delegation.
    pub derivation_reason: DerivationReason,
    /// Capabilities granted at this hop.
    pub granted_capabilities: CapabilitySet,
    /// When the delegation happened.
    pub derived_at: SystemTime,
}

/// Signature attesting a delegation (§4.8).
///
/// Signed by the **previous** principal in the chain over the
/// deterministic-CBOR encoding of [`DelegationReceiptPayload`]
/// with domain separation `b"kryphocron/v1/attribution-receipt/"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DelegationReceipt {
    /// Algorithm tag.
    pub algorithm: SignatureAlgorithm,
    /// Raw signature bytes.
    pub bytes: [u8; 64],
}

impl From<ClaimSignature> for DelegationReceipt {
    fn from(sig: ClaimSignature) -> Self {
        DelegationReceipt {
            algorithm: sig.algorithm,
            bytes: sig.bytes,
        }
    }
}

/// Receipt-verification failure (§4.8 round-5 patch — all six
/// variants).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReceiptVerificationFailure {
    /// Signature did not verify against the resolved key.
    #[error("receipt signature invalid")]
    SignatureInvalid,
    /// Previous principal's DID failed to resolve.
    #[error("previous principal unresolvable: {0}")]
    PreviousPrincipalUnresolvable(DidResolutionError),
    /// Receipt algorithm not in the allowlist.
    #[error("algorithm not accepted: {0:?}")]
    AlgorithmNotAccepted(SignatureAlgorithm),
    /// Receipt payload was structurally malformed.
    #[error("receipt malformed")]
    Malformed,
    /// Hop's `granted_capabilities` is not a subset of the
    /// previous hop's (or, for hop 0, of the origin's authorized
    /// set). §4.8 W13.
    #[error(
        "capability expansion at hop {hop}: attempted exceeds available"
    )]
    CapabilityExpansion {
        /// Hop index.
        hop: u8,
        /// Attempted capability set.
        attempted: CapabilitySet,
        /// Capability set the hop should have remained within.
        available: CapabilitySet,
    },
    /// Receipt's `previous_key_id` is not in the principal's
    /// current verification methods or rotation history.
    #[error("key not in rotation history: {previous_key_id:?}")]
    KeyNotInRotationHistory {
        /// The unresolvable key id.
        previous_key_id: KeyId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_verification_failure_has_six_variants() {
        // §4.8 round-5 patch commits exactly these six variants.
        // Pin them so future edits cannot silently drop one.
        let _v1 = ReceiptVerificationFailure::SignatureInvalid;
        let _v2 = ReceiptVerificationFailure::PreviousPrincipalUnresolvable(
            DidResolutionError::NotFound,
        );
        let _v3 = ReceiptVerificationFailure::AlgorithmNotAccepted(
            SignatureAlgorithm::Ed25519,
        );
        let _v4 = ReceiptVerificationFailure::Malformed;
        let _v5 = ReceiptVerificationFailure::CapabilityExpansion {
            hop: 0,
            attempted: CapabilitySet::empty(),
            available: CapabilitySet::empty(),
        };
        let _v6 = ReceiptVerificationFailure::KeyNotInRotationHistory {
            previous_key_id: KeyId::from_bytes([0; 32]),
        };
    }

    #[test]
    fn attribution_principal_did_accessor() {
        let p = AttributionPrincipal::User(Did::new("did:plc:example").unwrap());
        assert_eq!(p.did().as_str(), "did:plc:example");
        assert!(p.key_id().is_none());
    }

    #[test]
    fn attribution_entry_wire_carries_granted_capabilities_round_5() {
        // §4.8 round-5 patch: AttributionEntryWire has
        // granted_capabilities. Phase B verifies this field is
        // present so the receiving substrate can enforce W13
        // monotonicity.
        let entry = AttributionEntryWire {
            principal: AttributionPrincipal::User(Did::new("did:plc:u").unwrap()),
            derivation_reason: crate::ingress::DerivationReason::DropPrivilegeToAnonymous,
            derived_at: std::time::SystemTime::UNIX_EPOCH,
            granted_capabilities: CapabilitySet::empty(),
            receipt: DelegationReceipt {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0; 64],
            },
        };
        assert!(entry.granted_capabilities.is_empty());
    }

    #[test]
    fn delegation_receipt_payload_canonicalizes_principals_as_did_key_id_round_5() {
        // §4.8 round-5 patch: principals canonicalized as
        // (did, key_id) pairs, NOT full ServiceIdentity values.
        let p = DelegationReceiptPayload {
            previous_principal_did: Did::new("did:plc:from").unwrap(),
            previous_key_id: KeyId::from_bytes([1; 32]),
            recipient_principal_did: Did::new("did:plc:to").unwrap(),
            recipient_key_id: KeyId::from_bytes([2; 32]),
            derivation_reason: crate::ingress::DerivationReason::DropPrivilegeToAnonymous,
            granted_capabilities: CapabilitySet::empty(),
            derived_at: std::time::SystemTime::UNIX_EPOCH,
        };
        assert_eq!(p.previous_key_id, KeyId::from_bytes([1; 32]));
        assert_eq!(p.recipient_key_id, KeyId::from_bytes([2; 32]));
    }
}

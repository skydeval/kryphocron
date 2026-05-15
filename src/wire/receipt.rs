// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.8 attribution-chain wire format + per-entry delegation
//! receipts (round-4 + round-5 patches).
//!
//! Phase 4e wires the receipt-payload canonical CBOR encoder, the
//! [`sign_delegation_receipt`] helper for operator tooling that
//! signs delegation receipts, and the
//! [`ATTRIBUTION_RECEIPT_DOMAIN_TAG`] constant that domain-
//! separates receipt signatures from §4.8's other signing
//! contexts (capability-claim, sync-handshake, trust-declaration).

use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey};
use smallvec::SmallVec;
use std::time::SystemTime;
use thiserror::Error;

use crate::authority::capability::CapabilitySet;
use crate::identity::{KeyId, PublicKey, ServiceIdentity, SignatureAlgorithm};
use crate::ingress::{DerivationReason, MAX_CHAIN_DEPTH};
use crate::proto::Did;
use crate::resolver::DidResolutionError;
use crate::wire::canonical_cbor;

use super::signature::ClaimSignature;

/// §4.8 W12 / W8: domain-separation prefix for delegation
/// receipt signatures.
///
/// Distinct from [`crate::wire::CLAIM_DOMAIN_TAG`] (capability
/// claim), [`crate::trust::TRUST_DECLARATION_DOMAIN_TAG`]
/// (service trust declaration), and the four
/// [`crate::wire`]`::HELLO_DOMAIN_TAG` / `ACCEPT_DOMAIN_TAG`
/// / `REJECT_DOMAIN_TAG` / `ESTABLISHED_DOMAIN_TAG` (sync
/// handshake) tags. A receipt-shaped signature computed under
/// any other domain tag fails verification with
/// [`ReceiptVerificationFailure::SignatureInvalid`] — W8 cross-
/// domain-forgery defense.
pub(crate) const ATTRIBUTION_RECEIPT_DOMAIN_TAG: &[u8] =
    b"kryphocron/v1/attribution-receipt/";

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

// ============================================================
// §4.8 W12 — receipt payload canonical CBOR + signing helper.
// ============================================================

/// Canonical RFC 8949 §4.2 CBOR encoding of a
/// [`DelegationReceiptPayload`].
///
/// The encoding is stable across Rust struct-field ordering and
/// across any in-memory representation differences: the canonical
/// encoder sorts map keys length-then-bytewise per RFC 8949
/// §4.2.1. Receivers re-encode the decoded payload with this
/// helper and verify the result byte-equals the on-wire payload —
/// the round-trip check that closes the §7 round-4 non-canonicality
/// hazard symmetrically for receipts as Phase 4b did for
/// capability claims.
#[must_use]
pub(crate) fn delegation_receipt_payload_canonical_bytes(
    payload: &DelegationReceiptPayload,
) -> Vec<u8> {
    canonical_cbor::to_canonical_bytes(delegation_receipt_payload_value(payload))
}

fn delegation_receipt_payload_value(p: &DelegationReceiptPayload) -> Value {
    Value::Map(vec![
        (
            Value::Text("previous_principal_did".into()),
            Value::Text(p.previous_principal_did.as_str().to_string()),
        ),
        (
            Value::Text("previous_key_id".into()),
            Value::Bytes(p.previous_key_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("recipient_principal_did".into()),
            Value::Text(p.recipient_principal_did.as_str().to_string()),
        ),
        (
            Value::Text("recipient_key_id".into()),
            Value::Bytes(p.recipient_key_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("derivation_reason".into()),
            derivation_reason_value(&p.derivation_reason),
        ),
        (
            Value::Text("granted_capabilities".into()),
            capability_set_value(&p.granted_capabilities),
        ),
        (
            Value::Text("derived_at".into()),
            system_time_value(p.derived_at),
        ),
    ])
}

fn derivation_reason_value(r: &DerivationReason) -> Value {
    match r {
        DerivationReason::DropPrivilegeToAnonymous => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("drop_privilege_to_anonymous".into()),
        )]),
        DerivationReason::NarrowCapabilities { dropped } => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("narrow_capabilities".into())),
            (Value::Text("dropped".into()), capability_set_value(dropped)),
        ]),
        DerivationReason::ServiceToServiceDelegation { trust_declaration_id } => {
            Value::Map(vec![
                (
                    Value::Text("kind".into()),
                    Value::Text("service_to_service_delegation".into()),
                ),
                (
                    Value::Text("trust_declaration_id".into()),
                    Value::Bytes(trust_declaration_id.as_bytes().to_vec()),
                ),
            ])
        }
    }
}

fn capability_set_value(s: &CapabilitySet) -> Value {
    Value::Array(
        s.kinds()
            .iter()
            .map(|c| Value::Text(c.wire_name().to_string()))
            .collect(),
    )
}

fn system_time_value(t: SystemTime) -> Value {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH not supported")
        .as_secs();
    Value::Integer(secs.into())
}

/// Sign a [`DelegationReceiptPayload`] under the previous
/// principal's signing key, producing a [`DelegationReceipt`].
///
/// The signature covers the canonical-CBOR encoding of the
/// payload, prefixed with the crate-internal
/// `ATTRIBUTION_RECEIPT_DOMAIN_TAG`
/// (`b"kryphocron/v1/attribution-receipt/"`).
/// Operators producing delegation chains call this helper once per
/// hop with the previous principal's signing key; the resulting
/// receipt is paired with the recipient principal's
/// [`AttributionEntryWire`] in the wire chain.
///
/// All v1 receipts are Ed25519 (§7.5 / §4.8 algorithm allowlist).
#[must_use]
pub fn sign_delegation_receipt(
    payload: &DelegationReceiptPayload,
    signing_key: &SigningKey,
) -> DelegationReceipt {
    let canonical = delegation_receipt_payload_canonical_bytes(payload);
    let mut signing_input =
        Vec::with_capacity(ATTRIBUTION_RECEIPT_DOMAIN_TAG.len() + canonical.len());
    signing_input.extend_from_slice(ATTRIBUTION_RECEIPT_DOMAIN_TAG);
    signing_input.extend_from_slice(&canonical);
    let sig = signing_key.sign(&signing_input);
    DelegationReceipt {
        algorithm: SignatureAlgorithm::Ed25519,
        bytes: sig.to_bytes(),
    }
}

/// Verify a [`DelegationReceipt`] against the previous principal's
/// public key and the canonical encoding of the receipt's payload.
///
/// Used internally by the chain walker; not part of the public
/// surface because chain walking carries additional invariants
/// (rotation-history walking, capability monotonicity) the
/// receipt-only verifier does not enforce.
pub(crate) fn verify_delegation_receipt(
    payload: &DelegationReceiptPayload,
    receipt: &DelegationReceipt,
    public_key: &PublicKey,
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if receipt.algorithm != SignatureAlgorithm::Ed25519
        || public_key.algorithm != SignatureAlgorithm::Ed25519
    {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&public_key.bytes) else {
        return false;
    };
    let canonical = delegation_receipt_payload_canonical_bytes(payload);
    let mut signing_input =
        Vec::with_capacity(ATTRIBUTION_RECEIPT_DOMAIN_TAG.len() + canonical.len());
    signing_input.extend_from_slice(ATTRIBUTION_RECEIPT_DOMAIN_TAG);
    signing_input.extend_from_slice(&canonical);
    let sig = Signature::from_bytes(&receipt.bytes);
    vk.verify(&signing_input, &sig).is_ok()
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

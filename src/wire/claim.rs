// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.8 `CapabilityClaim` — the cross-service wire vocabulary.

use core::marker::PhantomData;
use std::time::{Duration, SystemTime};

use ciborium::Value;
use ed25519_dalek::Signer;
use thiserror::Error;

use crate::authority::capability::CapabilityKind;
use crate::authority::subjects::ResourceId;
use crate::identity::{KeyId, PublicKey, ServiceIdentity, SignatureAlgorithm, TraceId};
use crate::proto::Did;
use crate::sealed;

use super::canonical_cbor;
use super::nonce::ClaimNonce;
use super::receipt::{
    AttributionChainWire, AttributionEntryWire, AttributionPrincipal, DelegationReceipt,
};
use super::signature::ClaimSignature;

/// Maximum validity window for a [`CapabilityClaim`] (§4.8).
pub const MAX_CLAIM_VALIDITY: Duration = Duration::from_secs(600);

/// Maximum byte size of a deterministic-CBOR-encoded
/// [`CapabilityClaim`] (§7.6).
///
/// 4 KB before base64url encoding; after the ~33% expansion the
/// HTTP `Authorization` header value lands at ~5462 bytes plus
/// the `KryphocronClaim` scheme prefix. The substrate refuses to
/// mint claims it cannot transmit — failure is fail-fast at
/// issuance via [`ClaimConstructionError::ClaimTooLarge`] rather
/// than discover-at-transit.
pub const MAX_CAPABILITY_CLAIM_SIZE: usize = 4096;

/// Domain-separation tag for [`CapabilityClaim`] signatures
/// (§4.8 W8).
///
/// Signing input is `DOMAIN_TAG || canonical_cbor(payload)`.
/// Other §7 contexts use distinct tags
/// (`b"kryphocron/v1/attribution-receipt/"` for delegation
/// receipts in Phase 4e; service trust declarations in Phase 4c
/// and the sync handshake in Phase 4d will land their own).
/// Cross-domain signature reuse is foreclosed by tag distinctness.
pub(crate) const CLAIM_DOMAIN_TAG: &[u8] = b"kryphocron/v1/capability-claim/";

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
    /// Construct a self-originated [`CapabilityClaim`] (§4.8
    /// constructor).
    ///
    /// `signing_key` is the Ed25519 private key whose public half
    /// matches `issuer.key_material()`. Phase 4b enforces a
    /// defensive equality check between the derived public bytes
    /// and the issuer's declared key material; mismatch returns
    /// [`ClaimConstructionError::SigningFailed`]. Operators
    /// holding their service signing keys via KMS-equivalent
    /// machinery are responsible for keeping the key pair coherent.
    ///
    /// Validation order per §4.8:
    ///
    /// 1. `validity` ≤ [`MAX_CLAIM_VALIDITY`].
    /// 2. §4.8 W6: substrate-class and moderation-class
    ///    capabilities are never wire-eligible.
    /// 3. §4.8 W9 / W10: per-class scope restrictions; mixed-
    ///    class claims must satisfy *all* classes' restrictions.
    /// 4. Issuer / signing-key coherence.
    /// 5. Canonical CBOR encoding of the payload (every field
    ///    except `signature`).
    /// 6. §7.6 size ceiling: encoded payload ≤
    ///    [`MAX_CAPABILITY_CLAIM_SIZE`].
    /// 7. §4.8 W8: domain-separated Ed25519 signature with the
    ///    crate-internal `CLAIM_DOMAIN_TAG` constant
    ///    (`b"kryphocron/v1/capability-claim/"`) over the
    ///    canonical encoding.
    ///
    /// The constructed claim's `origin` is
    /// [`ClaimOrigin::SelfOriginated`]. Delegated-from-upstream
    /// construction (`ClaimOrigin::DelegatedFromUpstream`) is
    /// produced via [`CapabilityClaim::new_delegated`] using a
    /// pre-built receipt chain.
    ///
    /// # Errors
    ///
    /// See [`ClaimConstructionError`].
    pub fn new(
        issuer: ServiceIdentity,
        audience: ServiceIdentity,
        subject: Did,
        capabilities: Vec<CapabilityKind>,
        resource_scope: ResourceScope,
        nonce: ClaimNonce,
        trace_id: TraceId,
        validity: Duration,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, ClaimConstructionError> {
        // 1. Validity ceiling.
        if validity > MAX_CLAIM_VALIDITY {
            return Err(ClaimConstructionError::ValidityTooLong {
                requested: validity,
                max: MAX_CLAIM_VALIDITY,
            });
        }

        // 2. W6: substrate / moderation capabilities never on
        //    the wire.
        for cap in &capabilities {
            if !cap.is_wire_eligible() {
                return Err(ClaimConstructionError::NonWireEligibleCapability(*cap));
            }
        }

        // 3. W9 / W10: per-class scope restrictions.
        for cap in &capabilities {
            check_scope_for_class(*cap, &resource_scope)?;
        }

        // 4. Issuer / signing-key coherence. A mismatch produces
        //    a claim that fails verification at every receiver;
        //    surface it at construction so operators don't ship
        //    broken claims into the wild. The check is constant-
        //    time on 32 bytes — no information leak.
        let derived_public = signing_key.verifying_key().to_bytes();
        if derived_public != issuer.key_material().bytes {
            return Err(ClaimConstructionError::SigningFailed);
        }

        // Build the unsigned payload value.
        let now = SystemTime::now();
        let issued_at = now;
        let expires_at = now + validity;
        let origin = ClaimOrigin::SelfOriginated;

        // 5. Canonical-CBOR encode the payload (every field
        //    except `signature`).
        let canonical_bytes = encode_payload(
            &issuer,
            &audience,
            &subject,
            &origin,
            &capabilities,
            &resource_scope,
            &nonce,
            &trace_id,
            issued_at,
            expires_at,
        );

        // 6. §7.6 size ceiling.
        if canonical_bytes.len() > MAX_CAPABILITY_CLAIM_SIZE {
            return Err(ClaimConstructionError::ClaimTooLarge {
                size: canonical_bytes.len(),
                max: MAX_CAPABILITY_CLAIM_SIZE,
            });
        }

        // 7. W8 domain-separated Ed25519 signature.
        let mut signing_input =
            Vec::with_capacity(CLAIM_DOMAIN_TAG.len() + canonical_bytes.len());
        signing_input.extend_from_slice(CLAIM_DOMAIN_TAG);
        signing_input.extend_from_slice(&canonical_bytes);
        let sig = signing_key.sign(&signing_input);
        let signature = ClaimSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sig.to_bytes(),
        };

        Ok(CapabilityClaim {
            issuer,
            audience,
            subject,
            origin,
            capabilities,
            resource_scope,
            nonce,
            trace_id,
            issued_at,
            expires_at,
            signature,
            _private: PhantomData,
        })
    }

    /// Construct a delegated [`CapabilityClaim`] (§4.8 W11).
    ///
    /// Parallel to [`Self::new`] but for the
    /// [`ClaimOrigin::DelegatedFromUpstream`] case: the issuer is
    /// acting on behalf of an upstream principal, with the full
    /// delegation chain attached as `chain`. Every Phase 4b
    /// validation stage runs identically; the only structural
    /// difference is the `origin` field.
    ///
    /// **Pre-construction discipline.** The chain's per-hop
    /// receipts must be signed by their respective previous
    /// principals BEFORE this constructor is called — the
    /// constructor does NOT verify the chain's signatures (that's
    /// receive-side). Use [`crate::wire::sign_delegation_receipt`]
    /// to produce per-hop receipts; assemble the chain manually;
    /// pass to this constructor.
    ///
    /// **Empty-chain rejection.** A delegated claim with zero hops
    /// is malformed per §4.8 W11; rejected at construction with
    /// [`ClaimConstructionError::EmptyDelegationChain`]. Receive-
    /// side decoders apply the same rejection.
    ///
    /// **Size ceiling.** The chain contributes to the canonical
    /// CBOR size; deeply-nested chains can blow past
    /// [`MAX_CAPABILITY_CLAIM_SIZE`]. Operators producing chains
    /// near the depth limit should expect to manage chain depth
    /// against the size ceiling. Construction returns
    /// [`ClaimConstructionError::ClaimTooLarge`] if exceeded.
    ///
    /// # Errors
    ///
    /// See [`ClaimConstructionError`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_delegated(
        issuer: ServiceIdentity,
        audience: ServiceIdentity,
        subject: Did,
        capabilities: Vec<CapabilityKind>,
        resource_scope: ResourceScope,
        nonce: ClaimNonce,
        trace_id: TraceId,
        validity: Duration,
        chain: AttributionChainWire,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, ClaimConstructionError> {
        // 0. Empty-chain rejection per §4.8 W11. A delegated claim
        //    with zero hops carries no attribution evidence.
        if chain.entries.is_empty() {
            return Err(ClaimConstructionError::EmptyDelegationChain);
        }
        // 1. Validity ceiling.
        if validity > MAX_CLAIM_VALIDITY {
            return Err(ClaimConstructionError::ValidityTooLong {
                requested: validity,
                max: MAX_CLAIM_VALIDITY,
            });
        }
        // 2. W6: substrate / moderation never wire-eligible.
        for cap in &capabilities {
            if !cap.is_wire_eligible() {
                return Err(ClaimConstructionError::NonWireEligibleCapability(*cap));
            }
        }
        // 3. W9 / W10 per-class scope restrictions.
        for cap in &capabilities {
            check_scope_for_class(*cap, &resource_scope)?;
        }
        // 4. Issuer / signing-key coherence.
        let derived_public = signing_key.verifying_key().to_bytes();
        if derived_public != issuer.key_material().bytes {
            return Err(ClaimConstructionError::SigningFailed);
        }

        let now = SystemTime::now();
        let issued_at = now;
        let expires_at = now + validity;
        let origin = ClaimOrigin::DelegatedFromUpstream { chain };

        // 5. Canonical-CBOR encode the payload.
        let canonical_bytes = encode_payload(
            &issuer,
            &audience,
            &subject,
            &origin,
            &capabilities,
            &resource_scope,
            &nonce,
            &trace_id,
            issued_at,
            expires_at,
        );

        // 6. §7.6 size ceiling — chain bytes count too.
        if canonical_bytes.len() > MAX_CAPABILITY_CLAIM_SIZE {
            return Err(ClaimConstructionError::ClaimTooLarge {
                size: canonical_bytes.len(),
                max: MAX_CAPABILITY_CLAIM_SIZE,
            });
        }

        // 7. W8 domain-separated Ed25519 signature.
        let mut signing_input =
            Vec::with_capacity(CLAIM_DOMAIN_TAG.len() + canonical_bytes.len());
        signing_input.extend_from_slice(CLAIM_DOMAIN_TAG);
        signing_input.extend_from_slice(&canonical_bytes);
        let sig = signing_key.sign(&signing_input);
        let signature = ClaimSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sig.to_bytes(),
        };

        Ok(CapabilityClaim {
            issuer,
            audience,
            subject,
            origin,
            capabilities,
            resource_scope,
            nonce,
            trace_id,
            issued_at,
            expires_at,
            signature,
            _private: PhantomData,
        })
    }

    /// Crate-internal constructor for received claims. Reserved
    /// for [`crate::verification::verify_capability_claim`] after
    /// every §7.6 verification stage has succeeded; not reachable
    /// from outside `crate::wire` / `crate::verification`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_internal_received(
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
    ) -> Self {
        CapabilityClaim {
            issuer,
            audience,
            subject,
            origin,
            capabilities,
            resource_scope,
            nonce,
            trace_id,
            issued_at,
            expires_at,
            signature,
            _private: PhantomData,
        }
    }

    /// Re-emit the canonical CBOR encoding of this claim's
    /// signed payload (all fields except `signature`).
    ///
    /// Receivers re-encode the deserialized payload with this
    /// helper and verify the result byte-equals the on-wire
    /// payload — the round-trip check that closes the §7
    /// round-4 non-canonicality hazard. Senders use the same
    /// helper inside [`Self::new`] to produce signature input
    /// bytes.
    #[must_use]
    pub(crate) fn canonical_payload_bytes(&self) -> Vec<u8> {
        encode_payload(
            &self.issuer,
            &self.audience,
            &self.subject,
            &self.origin,
            &self.capabilities,
            &self.resource_scope,
            &self.nonce,
            &self.trace_id,
            self.issued_at,
            self.expires_at,
        )
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

// ============================================================
// §4.8 deterministic CBOR encoding for the wire payload.
// ============================================================

/// Encode the unsigned payload (every field except `signature`)
/// as canonical RFC 8949 §4.2 CBOR.
///
/// The shape is a top-level map with ten keys; nested values use
/// the encoders below. All map orderings are imposed by
/// [`canonical_cbor::canonicalize`] downstream of this builder,
/// so the per-builder `Value::Map(vec![...])` insertion order is
/// not load-bearing.
#[allow(clippy::too_many_arguments)]
fn encode_payload(
    issuer: &ServiceIdentity,
    audience: &ServiceIdentity,
    subject: &Did,
    origin: &ClaimOrigin,
    capabilities: &[CapabilityKind],
    resource_scope: &ResourceScope,
    nonce: &ClaimNonce,
    trace_id: &TraceId,
    issued_at: SystemTime,
    expires_at: SystemTime,
) -> Vec<u8> {
    let map = Value::Map(vec![
        (Value::Text("issuer".into()), service_identity_value(issuer)),
        (Value::Text("audience".into()), service_identity_value(audience)),
        (Value::Text("subject".into()), Value::Text(subject.as_str().to_string())),
        (Value::Text("origin".into()), claim_origin_value(origin)),
        (Value::Text("capabilities".into()), capabilities_value(capabilities)),
        (Value::Text("resource_scope".into()), resource_scope_value(resource_scope)),
        (Value::Text("nonce".into()), Value::Bytes(nonce.as_bytes().to_vec())),
        (Value::Text("trace_id".into()), Value::Bytes(trace_id.as_bytes().to_vec())),
        (Value::Text("issued_at".into()), system_time_value(issued_at)),
        (Value::Text("expires_at".into()), system_time_value(expires_at)),
    ]);
    canonical_cbor::to_canonical_bytes(map)
}

/// Encode a [`ServiceIdentity`] as a four-field map. The
/// optional `rotation_evidence` field is intentionally **not**
/// included: §4.8 commits that non-signing-key parts of
/// `ServiceIdentity` may change without affecting the identity's
/// signing semantics, so binding signatures to the rotation
/// chain would invalidate claims after legitimate, non-signing
/// rotation events.
fn service_identity_value(s: &ServiceIdentity) -> Value {
    Value::Map(vec![
        (Value::Text("did".into()), Value::Text(s.service_did().as_str().to_string())),
        (Value::Text("key_id".into()), Value::Bytes(s.key_id().as_bytes().to_vec())),
        (Value::Text("key_alg".into()), Value::Text(signature_alg_name(s.key_material().algorithm).into())),
        (Value::Text("key_material".into()), Value::Bytes(s.key_material().bytes.to_vec())),
    ])
}

/// Stable wire name for the [`SignatureAlgorithm`] enum.
fn signature_alg_name(a: SignatureAlgorithm) -> &'static str {
    match a {
        SignatureAlgorithm::Ed25519 => "Ed25519",
        SignatureAlgorithm::Es256 => "Es256",
        SignatureAlgorithm::Es256K => "Es256K",
    }
}

fn capabilities_value(caps: &[CapabilityKind]) -> Value {
    Value::Array(
        caps.iter()
            .map(|c| Value::Text(c.wire_name().to_string()))
            .collect(),
    )
}

fn resource_scope_value(s: &ResourceScope) -> Value {
    match s {
        ResourceScope::Resource(rid) => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("resource".into())),
            (
                Value::Text("value".into()),
                Value::Map(vec![
                    (Value::Text("did".into()), Value::Text(rid.did().as_str().to_string())),
                    (Value::Text("nsid".into()), Value::Text(rid.nsid().as_str().to_string())),
                    (Value::Text("rkey".into()), Value::Text(rid.rkey().as_str().to_string())),
                ]),
            ),
        ]),
        ResourceScope::AllResourcesOwnedBy(did) => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("all_resources_owned_by".into())),
            (Value::Text("value".into()), Value::Text(did.as_str().to_string())),
        ]),
        ResourceScope::ClassWideAdministrative => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("class_wide_administrative".into()),
        )]),
    }
}

fn claim_origin_value(o: &ClaimOrigin) -> Value {
    match o {
        ClaimOrigin::SelfOriginated => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("self_originated".into()),
        )]),
        ClaimOrigin::DelegatedFromUpstream { chain } => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("delegated_from_upstream".into())),
            (Value::Text("chain".into()), attribution_chain_value(chain)),
        ]),
    }
}

fn attribution_chain_value(c: &AttributionChainWire) -> Value {
    Value::Map(vec![
        (Value::Text("origin".into()), attribution_principal_value(&c.origin)),
        (
            Value::Text("entries".into()),
            Value::Array(c.entries.iter().map(attribution_entry_value).collect()),
        ),
    ])
}

fn attribution_principal_value(p: &AttributionPrincipal) -> Value {
    match p {
        AttributionPrincipal::User(did) => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("user".into())),
            (Value::Text("did".into()), Value::Text(did.as_str().to_string())),
        ]),
        AttributionPrincipal::Service(s) => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("service".into())),
            (Value::Text("identity".into()), service_identity_value(s)),
        ]),
    }
}

fn attribution_entry_value(e: &AttributionEntryWire) -> Value {
    Value::Map(vec![
        (Value::Text("principal".into()), attribution_principal_value(&e.principal)),
        (
            Value::Text("derivation_reason".into()),
            derivation_reason_value(&e.derivation_reason),
        ),
        (Value::Text("derived_at".into()), system_time_value(e.derived_at)),
        (
            Value::Text("granted_capabilities".into()),
            Value::Array(
                e.granted_capabilities
                    .kinds()
                    .iter()
                    .map(|c| Value::Text(c.wire_name().to_string()))
                    .collect(),
            ),
        ),
        (Value::Text("receipt".into()), receipt_value(&e.receipt)),
    ])
}

fn derivation_reason_value(r: &crate::ingress::DerivationReason) -> Value {
    use crate::ingress::DerivationReason;
    match r {
        DerivationReason::DropPrivilegeToAnonymous => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("drop_privilege_to_anonymous".into()),
        )]),
        DerivationReason::NarrowCapabilities { dropped } => Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("narrow_capabilities".into())),
            (
                Value::Text("dropped".into()),
                Value::Array(
                    dropped
                        .kinds()
                        .iter()
                        .map(|c| Value::Text(c.wire_name().to_string()))
                        .collect(),
                ),
            ),
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

fn receipt_value(r: &DelegationReceipt) -> Value {
    Value::Map(vec![
        (Value::Text("alg".into()), Value::Text(signature_alg_name(r.algorithm).into())),
        (Value::Text("bytes".into()), Value::Bytes(r.bytes.to_vec())),
    ])
}

/// Encode a [`SystemTime`] as a CBOR unsigned integer (Unix
/// epoch seconds). Times before the epoch are not part of the
/// crate's threat model — encoding panics if presented one. The
/// constructors in this module always pass current `SystemTime`
/// values from `now()` plus / minus bounded durations, so the
/// constraint is structural.
fn system_time_value(t: SystemTime) -> Value {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH not supported")
        .as_secs();
    Value::Integer(secs.into())
}

// ============================================================
// Helpers used at receive-time decoding (Phase 4b's
// `verify_capability_claim` reaches in here through the
// `verification` submodule).
// ============================================================

/// Decode a canonical-CBOR byte stream into the constituent
/// payload fields.
///
/// Returns `Err(())` for any structural problem; callers
/// translate to the appropriate [`crate::ClaimVerificationError`]
/// variant. The returned tuple matches
/// [`CapabilityClaim::new_internal_received`]'s parameter order
/// minus the signature.
#[allow(clippy::type_complexity, clippy::too_many_lines, dead_code)]
pub(crate) fn decode_payload(
    bytes: &[u8],
) -> Result<
    (
        ServiceIdentity, // issuer
        ServiceIdentity, // audience
        Did,             // subject
        ClaimOrigin,     // origin
        Vec<CapabilityKind>,
        ResourceScope,
        ClaimNonce,
        TraceId,
        SystemTime, // issued_at
        SystemTime, // expires_at
    ),
    (),
> {
    let value = canonical_cbor::from_bytes(bytes)?;
    let map = into_map(&value)?;
    Ok((
        decode_service_identity(map_get(&map, "issuer")?)?,
        decode_service_identity(map_get(&map, "audience")?)?,
        decode_did(map_get(&map, "subject")?)?,
        decode_claim_origin(map_get(&map, "origin")?)?,
        decode_capabilities(map_get(&map, "capabilities")?)?,
        decode_resource_scope(map_get(&map, "resource_scope")?)?,
        decode_nonce(map_get(&map, "nonce")?)?,
        decode_trace_id(map_get(&map, "trace_id")?)?,
        decode_system_time(map_get(&map, "issued_at")?)?,
        decode_system_time(map_get(&map, "expires_at")?)?,
    ))
}

// ============================================================
// Wire envelope (signing payload + signature) encoder/decoder.
// ============================================================

/// Encode a constructed [`CapabilityClaim`] as wire-format
/// bytes: the canonical CBOR of all fields including the
/// `signature` field.
///
/// The wire envelope is what the `KryphocronClaim` HTTP
/// authorization scheme carries (after base64url encoding) and
/// what the sync-channel framed-binary path carries (post-
/// handshake). Receivers verify the signature against the
/// canonical encoding of the same map *minus* the `signature`
/// key (the `canonical_payload_bytes` crate-internal helper).
impl CapabilityClaim {
    /// Encode this claim for wire transmission.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let map = Value::Map(vec![
            (Value::Text("issuer".into()), service_identity_value(&self.issuer)),
            (Value::Text("audience".into()), service_identity_value(&self.audience)),
            (
                Value::Text("subject".into()),
                Value::Text(self.subject.as_str().to_string()),
            ),
            (Value::Text("origin".into()), claim_origin_value(&self.origin)),
            (
                Value::Text("capabilities".into()),
                capabilities_value(&self.capabilities),
            ),
            (
                Value::Text("resource_scope".into()),
                resource_scope_value(&self.resource_scope),
            ),
            (
                Value::Text("nonce".into()),
                Value::Bytes(self.nonce.as_bytes().to_vec()),
            ),
            (
                Value::Text("trace_id".into()),
                Value::Bytes(self.trace_id.as_bytes().to_vec()),
            ),
            (Value::Text("issued_at".into()), system_time_value(self.issued_at)),
            (Value::Text("expires_at".into()), system_time_value(self.expires_at)),
            (Value::Text("signature".into()), claim_signature_value(&self.signature)),
        ]);
        canonical_cbor::to_canonical_bytes(map)
    }
}

fn claim_signature_value(s: &ClaimSignature) -> Value {
    Value::Map(vec![
        (Value::Text("alg".into()), Value::Text(signature_alg_name(s.algorithm).into())),
        (Value::Text("bytes".into()), Value::Bytes(s.bytes.to_vec())),
    ])
}

/// Decode a wire envelope into its constituent fields.
///
/// Returns `Err(())` for any structural problem; callers
/// translate to the appropriate
/// [`crate::ClaimVerificationError`] variant.
#[allow(clippy::type_complexity)]
pub(crate) fn decode_wire(
    bytes: &[u8],
) -> Result<
    (
        ServiceIdentity,
        ServiceIdentity,
        Did,
        ClaimOrigin,
        Vec<CapabilityKind>,
        ResourceScope,
        ClaimNonce,
        TraceId,
        SystemTime,
        SystemTime,
        ClaimSignature,
    ),
    (),
> {
    let value = canonical_cbor::from_bytes(bytes)?;
    let map = into_map(&value)?;
    let signature = decode_claim_signature(map_get(&map, "signature")?)?;
    Ok((
        decode_service_identity(map_get(&map, "issuer")?)?,
        decode_service_identity(map_get(&map, "audience")?)?,
        decode_did(map_get(&map, "subject")?)?,
        decode_claim_origin(map_get(&map, "origin")?)?,
        decode_capabilities(map_get(&map, "capabilities")?)?,
        decode_resource_scope(map_get(&map, "resource_scope")?)?,
        decode_nonce(map_get(&map, "nonce")?)?,
        decode_trace_id(map_get(&map, "trace_id")?)?,
        decode_system_time(map_get(&map, "issued_at")?)?,
        decode_system_time(map_get(&map, "expires_at")?)?,
        signature,
    ))
}

fn decode_claim_signature(v: &Value) -> Result<ClaimSignature, ()> {
    let map = into_map(v)?;
    let alg_str = match map_get(&map, "alg")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    let algorithm = decode_signature_alg(alg_str).ok_or(())?;
    let bytes = decode_bytes(map_get(&map, "bytes")?)?;
    let bytes_arr: [u8; 64] = bytes.try_into().map_err(|_| ())?;
    Ok(ClaimSignature {
        algorithm,
        bytes: bytes_arr,
    })
}

/// Round-trip-canonicality check: re-encode a decoded value and
/// compare to the input bytes. Used at receive-time to reject
/// non-canonical wire payloads as `Malformed` per the §7
/// round-4 hazard.
#[must_use]
pub(crate) fn wire_bytes_are_canonical(bytes: &[u8]) -> bool {
    let Ok(value) = canonical_cbor::from_bytes(bytes) else {
        return false;
    };
    let re_encoded = canonical_cbor::to_canonical_bytes(value);
    re_encoded == bytes
}

fn into_map(v: &Value) -> Result<Vec<(Value, Value)>, ()> {
    match v {
        Value::Map(entries) => Ok(entries.clone()),
        _ => Err(()),
    }
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a Value, ()> {
    map.iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == key => Some(v),
            _ => None,
        })
        .ok_or(())
}

fn decode_did(v: &Value) -> Result<Did, ()> {
    match v {
        Value::Text(s) => Did::new(s).map_err(|_| ()),
        _ => Err(()),
    }
}

fn decode_service_identity(v: &Value) -> Result<ServiceIdentity, ()> {
    let map = into_map(v)?;
    let did = decode_did(map_get(&map, "did")?)?;
    let key_id_bytes = decode_bytes(map_get(&map, "key_id")?)?;
    let key_id_arr: [u8; 32] = key_id_bytes.try_into().map_err(|_| ())?;
    let key_alg_str = match map_get(&map, "key_alg")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    let algorithm = decode_signature_alg(key_alg_str).ok_or(())?;
    let key_material_bytes = decode_bytes(map_get(&map, "key_material")?)?;
    let key_material_arr: [u8; 32] = key_material_bytes.try_into().map_err(|_| ())?;
    Ok(ServiceIdentity::new_internal(
        did,
        KeyId::from_bytes(key_id_arr),
        PublicKey {
            algorithm,
            bytes: key_material_arr,
        },
        None,
    ))
}

fn decode_signature_alg(s: &str) -> Option<SignatureAlgorithm> {
    Some(match s {
        "Ed25519" => SignatureAlgorithm::Ed25519,
        "Es256" => SignatureAlgorithm::Es256,
        "Es256K" => SignatureAlgorithm::Es256K,
        _ => return None,
    })
}

fn decode_bytes(v: &Value) -> Result<Vec<u8>, ()> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(()),
    }
}

fn decode_capabilities(v: &Value) -> Result<Vec<CapabilityKind>, ()> {
    match v {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Text(s) => CapabilityKind::from_wire_name(s).ok_or(()),
                _ => Err(()),
            })
            .collect(),
        _ => Err(()),
    }
}

fn decode_resource_scope(v: &Value) -> Result<ResourceScope, ()> {
    let map = into_map(v)?;
    let kind = match map_get(&map, "kind")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    match kind {
        "resource" => {
            let value_map = into_map(map_get(&map, "value")?)?;
            let did = decode_did(map_get(&value_map, "did")?)?;
            let nsid_str = match map_get(&value_map, "nsid")? {
                Value::Text(s) => s.as_str(),
                _ => return Err(()),
            };
            let nsid = crate::Nsid::new(nsid_str).map_err(|_| ())?;
            let rkey_str = match map_get(&value_map, "rkey")? {
                Value::Text(s) => s.as_str(),
                _ => return Err(()),
            };
            let rkey = crate::Rkey::new(rkey_str).map_err(|_| ())?;
            Ok(ResourceScope::Resource(ResourceId::new(did, nsid, rkey)))
        }
        "all_resources_owned_by" => {
            let did = decode_did(map_get(&map, "value")?)?;
            Ok(ResourceScope::AllResourcesOwnedBy(did))
        }
        "class_wide_administrative" => Ok(ResourceScope::ClassWideAdministrative),
        _ => Err(()),
    }
}

fn decode_claim_origin(v: &Value) -> Result<ClaimOrigin, ()> {
    let map = into_map(v)?;
    let kind = match map_get(&map, "kind")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    match kind {
        "self_originated" => Ok(ClaimOrigin::SelfOriginated),
        "delegated_from_upstream" => {
            // Phase 4e wires full chain decode. The §4.8 W11 wire
            // chain decodes structurally; per-hop signature
            // verification (W12) and capability monotonicity
            // (W13) are the verifier's responsibility via
            // verify_attribution_chain. Empty chains are
            // structurally malformed (§4.8: a delegated claim
            // with zero hops carries no attribution evidence).
            let chain = decode_attribution_chain(map_get(&map, "chain")?)?;
            if chain.entries.is_empty() {
                return Err(());
            }
            Ok(ClaimOrigin::DelegatedFromUpstream { chain })
        }
        _ => Err(()),
    }
}

fn decode_attribution_chain(v: &Value) -> Result<AttributionChainWire, ()> {
    let m = into_map(v)?;
    let origin = decode_attribution_principal(map_get(&m, "origin")?)?;
    let entries_value = map_get(&m, "entries")?;
    let entries_arr = match entries_value {
        Value::Array(a) => a,
        _ => return Err(()),
    };
    if entries_arr.len() > crate::ingress::MAX_CHAIN_DEPTH {
        return Err(());
    }
    let mut entries: smallvec::SmallVec<[AttributionEntryWire; crate::ingress::MAX_CHAIN_DEPTH]> =
        smallvec::SmallVec::new();
    for item in entries_arr {
        entries.push(decode_attribution_entry(item)?);
    }
    Ok(AttributionChainWire { origin, entries })
}

fn decode_attribution_principal(v: &Value) -> Result<AttributionPrincipal, ()> {
    let m = into_map(v)?;
    let kind = match map_get(&m, "kind")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    match kind {
        "user" => {
            let did = decode_did(map_get(&m, "did")?)?;
            Ok(AttributionPrincipal::User(did))
        }
        "service" => {
            let identity = decode_service_identity(map_get(&m, "identity")?)?;
            Ok(AttributionPrincipal::Service(identity))
        }
        _ => Err(()),
    }
}

fn decode_attribution_entry(v: &Value) -> Result<AttributionEntryWire, ()> {
    let m = into_map(v)?;
    let principal = decode_attribution_principal(map_get(&m, "principal")?)?;
    let derivation_reason =
        decode_derivation_reason(map_get(&m, "derivation_reason")?)?;
    let derived_at = decode_system_time(map_get(&m, "derived_at")?)?;
    let granted_capabilities = decode_capability_set(map_get(&m, "granted_capabilities")?)?;
    let receipt = decode_delegation_receipt(map_get(&m, "receipt")?)?;
    Ok(AttributionEntryWire {
        principal,
        derivation_reason,
        derived_at,
        granted_capabilities,
        receipt,
    })
}

fn decode_derivation_reason(v: &Value) -> Result<crate::ingress::DerivationReason, ()> {
    use crate::ingress::DerivationReason;
    let m = into_map(v)?;
    let kind = match map_get(&m, "kind")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    match kind {
        "drop_privilege_to_anonymous" => Ok(DerivationReason::DropPrivilegeToAnonymous),
        "narrow_capabilities" => {
            let dropped = decode_capability_set(map_get(&m, "dropped")?)?;
            Ok(DerivationReason::NarrowCapabilities { dropped })
        }
        "service_to_service_delegation" => {
            let id_bytes = match map_get(&m, "trust_declaration_id")? {
                Value::Bytes(b) if b.len() == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    a
                }
                _ => return Err(()),
            };
            Ok(DerivationReason::ServiceToServiceDelegation {
                trust_declaration_id: crate::ingress::TrustDeclarationId::from_bytes(id_bytes),
            })
        }
        _ => Err(()),
    }
}

fn decode_capability_set(
    v: &Value,
) -> Result<crate::authority::capability::CapabilitySet, ()> {
    let arr = match v {
        Value::Array(a) => a,
        _ => return Err(()),
    };
    let mut kinds: Vec<CapabilityKind> = Vec::with_capacity(arr.len());
    for item in arr {
        let s = match item {
            Value::Text(s) => s.as_str(),
            _ => return Err(()),
        };
        kinds.push(CapabilityKind::from_wire_name(s).ok_or(())?);
    }
    Ok(crate::authority::capability::CapabilitySet::from_kinds(kinds))
}

fn decode_delegation_receipt(v: &Value) -> Result<DelegationReceipt, ()> {
    let m = into_map(v)?;
    let alg = match map_get(&m, "alg")? {
        Value::Text(s) => decode_signature_alg(s).ok_or(())?,
        _ => return Err(()),
    };
    let bytes: [u8; 64] = match map_get(&m, "bytes")? {
        Value::Bytes(b) if b.len() == 64 => {
            let mut a = [0u8; 64];
            a.copy_from_slice(b);
            a
        }
        _ => return Err(()),
    };
    Ok(DelegationReceipt {
        algorithm: alg,
        bytes,
    })
}

fn decode_nonce(v: &Value) -> Result<ClaimNonce, ()> {
    let bytes = decode_bytes(v)?;
    let arr: [u8; 16] = bytes.try_into().map_err(|_| ())?;
    Ok(ClaimNonce::from_bytes(arr))
}

fn decode_trace_id(v: &Value) -> Result<TraceId, ()> {
    let bytes = decode_bytes(v)?;
    let arr: [u8; 16] = bytes.try_into().map_err(|_| ())?;
    Ok(TraceId::from_bytes(arr))
}

fn decode_system_time(v: &Value) -> Result<SystemTime, ()> {
    match v {
        Value::Integer(i) => {
            let secs: u64 = (*i).try_into().map_err(|_| ())?;
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        }
        _ => Err(()),
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
    /// Signing operation failed. Currently surfaces the
    /// issuer-vs-signing-key coherence check (a claim built with
    /// a signing key whose public half doesn't match
    /// `issuer.key_material()` would fail verification at every
    /// receiver; we surface it at construction so operators don't
    /// ship broken claims).
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
    /// `new_delegated` was called with a chain whose `entries`
    /// vector is empty (§4.8: a delegated claim with zero hops is
    /// malformed).
    #[error("delegation chain has zero entries")]
    EmptyDelegationChain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::capability::CapabilityKind;
    use crate::authority::subjects::ResourceId;
    use crate::identity::{KeyId, PublicKey, ServiceIdentity, SignatureAlgorithm};
    use crate::proto::{Did, Nsid, Rkey};
    use ed25519_dalek::SigningKey;

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn fixed_service_identity(did: &str) -> ServiceIdentity {
        let signing = fixed_signing_key();
        ServiceIdentity::new_internal(
            Did::new(did).unwrap(),
            KeyId::from_bytes([1u8; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: signing.verifying_key().to_bytes(),
            },
            None,
        )
    }

    fn unmatched_service_identity(did: &str) -> ServiceIdentity {
        // Different `key_material` from `fixed_signing_key()`'s
        // public — exercises the issuer/signing-key coherence
        // check.
        let other = SigningKey::from_bytes(&[42u8; 32]);
        ServiceIdentity::new_internal(
            Did::new(did).unwrap(),
            KeyId::from_bytes([2u8; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: other.verifying_key().to_bytes(),
            },
            None,
        )
    }

    fn sample_resource() -> ResourceId {
        ResourceId::new(
            Did::new("did:plc:owner").unwrap(),
            Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            Rkey::new("samplerkey").unwrap(),
        )
    }

    #[test]
    fn validity_ceiling_pinned_at_600s() {
        // §4.8 commits MAX_CLAIM_VALIDITY = 600 seconds.
        assert_eq!(MAX_CLAIM_VALIDITY, Duration::from_secs(600));
    }

    #[test]
    fn max_capability_claim_size_pinned_at_4096() {
        // §7.6 commits MAX_CAPABILITY_CLAIM_SIZE = 4096 bytes.
        assert_eq!(MAX_CAPABILITY_CLAIM_SIZE, 4096);
    }

    #[test]
    fn claim_domain_tag_pinned_per_4_8_w8() {
        // §4.8 W8 commits this exact tag string. Crate-internal
        // visibility so other §7 contexts (receipts, handshakes,
        // trust declarations) cannot accidentally reuse it.
        assert_eq!(CLAIM_DOMAIN_TAG, b"kryphocron/v1/capability-claim/");
    }

    #[test]
    fn scope_variant_name_round_trips() {
        let r = ResourceScope::ClassWideAdministrative;
        assert_eq!(
            ScopeVariantName::from(&r),
            ScopeVariantName::ClassWideAdministrative
        );
    }

    #[test]
    fn happy_path_constructs_self_originated_claim() {
        let signing = fixed_signing_key();
        let issuer = fixed_service_identity("did:web:issuer.example");
        let audience = fixed_service_identity("did:web:audience.example");
        let claim = CapabilityClaim::new(
            issuer,
            audience,
            Did::new("did:plc:subject").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0xAB; 16]),
            TraceId::from_bytes([0xCD; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap();

        assert!(matches!(claim.origin(), ClaimOrigin::SelfOriginated));
        assert_eq!(claim.signature().algorithm, SignatureAlgorithm::Ed25519);
        // Sanity: the canonical payload is non-empty and within
        // the 4 KB ceiling.
        let bytes = claim.canonical_payload_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= MAX_CAPABILITY_CLAIM_SIZE);
    }

    #[test]
    fn validity_too_long_returns_validity_too_long() {
        let signing = fixed_signing_key();
        let err = CapabilityClaim::new(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            MAX_CLAIM_VALIDITY + Duration::from_secs(1),
            &signing,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimConstructionError::ValidityTooLong { .. }));
    }

    #[test]
    fn substrate_capability_returns_non_wire_eligible() {
        // §4.8 W6: substrate-class never wire-shippable.
        let signing = fixed_signing_key();
        let err = CapabilityClaim::new(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ScanShard],
            ResourceScope::ClassWideAdministrative,
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClaimConstructionError::NonWireEligibleCapability(CapabilityKind::ScanShard)
        ));
    }

    #[test]
    fn moderation_capability_returns_non_wire_eligible() {
        let signing = fixed_signing_key();
        let err = CapabilityClaim::new(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ModeratorRead],
            ResourceScope::ClassWideAdministrative,
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClaimConstructionError::NonWireEligibleCapability(CapabilityKind::ModeratorRead)
        ));
    }

    #[test]
    fn user_capability_with_non_resource_scope_returns_scope_not_permitted() {
        // §4.8 W9: user-class restricted to Resource scope.
        let signing = fixed_signing_key();
        let err = CapabilityClaim::new(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::ClassWideAdministrative,
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClaimConstructionError::ScopeNotPermittedForClass {
                capability: CapabilityKind::ViewPrivate,
                scope_variant: ScopeVariantName::ClassWideAdministrative,
            }
        ));
    }

    #[test]
    fn mixed_class_with_user_and_channel_uses_most_restrictive() {
        // §4.8 W10: mixed-class claims must satisfy ALL classes'
        // restrictions. User-class requires Resource scope; if a
        // channel-class capability is included with a non-Resource
        // scope, the user-class check fails.
        let signing = fixed_signing_key();
        let err = CapabilityClaim::new(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate, CapabilityKind::EmitToSyncChannel],
            ResourceScope::AllResourcesOwnedBy(Did::new("did:plc:owner").unwrap()),
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap_err();
        // The user-class check fires first; channel-class would
        // accept AllResourcesOwnedBy but the most-restrictive
        // class wins.
        assert!(matches!(
            err,
            ClaimConstructionError::ScopeNotPermittedForClass { .. }
        ));
    }

    #[test]
    fn issuer_signing_key_mismatch_returns_signing_failed() {
        // Defensive check: issuer's declared key_material doesn't
        // match the public derived from signing_key.
        let signing = fixed_signing_key();
        let issuer_with_other_key = unmatched_service_identity("did:web:i");
        let err = CapabilityClaim::new(
            issuer_with_other_key,
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimConstructionError::SigningFailed));
    }

    #[test]
    fn canonical_payload_round_trips_through_decode() {
        // Encode → decode → re-encode → byte-equals. The receive-
        // side defensive check Phase 4b's verify_capability_claim
        // will use lands in C4; this test pins the round-trip
        // contract at the encoder boundary.
        let signing = fixed_signing_key();
        let issuer = fixed_service_identity("did:web:issuer.example");
        let audience = fixed_service_identity("did:web:audience.example");
        let claim = CapabilityClaim::new(
            issuer,
            audience,
            Did::new("did:plc:subject").unwrap(),
            vec![CapabilityKind::ViewPrivate, CapabilityKind::ParticipatePrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0xAB; 16]),
            TraceId::from_bytes([0xCD; 16]),
            Duration::from_secs(60),
            &signing,
        )
        .unwrap();

        let bytes = claim.canonical_payload_bytes();
        let decoded = decode_payload(&bytes).unwrap();
        let (
            d_issuer,
            d_audience,
            d_subject,
            d_origin,
            d_capabilities,
            d_resource_scope,
            d_nonce,
            d_trace_id,
            d_issued_at,
            d_expires_at,
        ) = decoded;
        let re_encoded = encode_payload(
            &d_issuer,
            &d_audience,
            &d_subject,
            &d_origin,
            &d_capabilities,
            &d_resource_scope,
            &d_nonce,
            &d_trace_id,
            d_issued_at,
            d_expires_at,
        );
        assert_eq!(bytes, re_encoded);
    }

    // ============================================================
    // Phase 4e — new_delegated + chain decoder tests.
    // ============================================================

    use crate::wire::{sign_delegation_receipt, DelegationReceiptPayload};

    fn build_one_hop_chain() -> AttributionChainWire {
        // Origin: a service principal A that signs a single-hop
        // chain delegating to recipient B.
        let sk_a = SigningKey::from_bytes(&[0xA0u8; 32]);
        let pk_a = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sk_a.verifying_key().to_bytes(),
        };
        let kid_a = KeyId::from_bytes([0xA0; 32]);
        let did_a = Did::new("did:plc:originservice00000000").unwrap();
        let identity_a = ServiceIdentity::new_internal(did_a.clone(), kid_a, pk_a, None);

        let did_b = Did::new("did:plc:recipientservice00000").unwrap();
        let kid_b = KeyId::from_bytes([0xB0; 32]);
        let pk_b = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: SigningKey::from_bytes(&[0xB0u8; 32]).verifying_key().to_bytes(),
        };
        let identity_b = ServiceIdentity::new_internal(did_b.clone(), kid_b, pk_b, None);

        let granted = crate::authority::capability::CapabilitySet::from_kinds(vec![
            CapabilityKind::ViewPrivate,
        ]);
        let derived_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let payload = DelegationReceiptPayload {
            previous_principal_did: did_a.clone(),
            previous_key_id: kid_a,
            recipient_principal_did: did_b.clone(),
            recipient_key_id: kid_b,
            derivation_reason: crate::ingress::DerivationReason::DropPrivilegeToAnonymous,
            granted_capabilities: granted.clone(),
            derived_at,
        };
        let receipt = sign_delegation_receipt(&payload, &sk_a);
        let entry = AttributionEntryWire {
            principal: AttributionPrincipal::Service(identity_b),
            derivation_reason: crate::ingress::DerivationReason::DropPrivilegeToAnonymous,
            derived_at,
            granted_capabilities: granted,
            receipt,
        };
        AttributionChainWire {
            origin: AttributionPrincipal::Service(identity_a),
            entries: smallvec::smallvec![entry],
        }
    }

    /// `new_delegated` happy path — a one-hop chain produces a
    /// `CapabilityClaim` whose origin is `DelegatedFromUpstream`.
    #[test]
    fn new_delegated_constructs_with_one_hop_chain() {
        let signing = fixed_signing_key();
        let chain = build_one_hop_chain();
        let claim = CapabilityClaim::new_delegated(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            chain,
            &signing,
        )
        .unwrap();
        assert!(matches!(claim.origin(), ClaimOrigin::DelegatedFromUpstream { .. }));
    }

    /// `new_delegated` rejects empty chains structurally.
    #[test]
    fn new_delegated_rejects_empty_chain() {
        let signing = fixed_signing_key();
        let empty_chain = AttributionChainWire {
            origin: AttributionPrincipal::User(Did::new("did:plc:u").unwrap()),
            entries: smallvec::SmallVec::new(),
        };
        let err = CapabilityClaim::new_delegated(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            empty_chain,
            &signing,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimConstructionError::EmptyDelegationChain));
    }

    /// Wire round-trip: a delegated claim's wire bytes decode back
    /// to the same chain shape (canonicality holds).
    #[test]
    fn delegated_origin_wire_round_trip() {
        let signing = fixed_signing_key();
        let chain = build_one_hop_chain();
        let claim = CapabilityClaim::new_delegated(
            fixed_service_identity("did:web:i"),
            fixed_service_identity("did:web:a"),
            Did::new("did:plc:s").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource()),
            ClaimNonce::from_bytes([0; 16]),
            TraceId::from_bytes([0; 16]),
            Duration::from_secs(60),
            chain,
            &signing,
        )
        .unwrap();
        let bytes = claim.canonical_payload_bytes();
        let decoded = decode_payload(&bytes).unwrap();
        let (
            d_issuer, d_audience, d_subject, d_origin,
            d_capabilities, d_resource_scope, d_nonce,
            d_trace_id, d_issued_at, d_expires_at,
        ) = decoded;
        assert!(matches!(d_origin, ClaimOrigin::DelegatedFromUpstream { .. }));
        let re_encoded = encode_payload(
            &d_issuer, &d_audience, &d_subject, &d_origin,
            &d_capabilities, &d_resource_scope, &d_nonce,
            &d_trace_id, d_issued_at, d_expires_at,
        );
        assert_eq!(bytes, re_encoded);
    }
}

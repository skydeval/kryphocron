// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §7.4 service trust declarations — verification path.
//!
//! Trust declarations are minted by operator tooling, NOT by the
//! substrate. The crate provides the verification path
//! ([`crate::trust::verify_trust_declaration`]) and the type shape
//! ([`crate::ingress::ServiceTrustDeclaration`]); construction is
//! operator-managed (typically a CLI signing with a hardware-token-
//! held trust-root key).
//!
//! Verification:
//!
//! 1. CBOR-decode the wire bytes; round-trip canonicality check
//!    (closes the §7 round-4 hazard, mirror of capability-claim
//!    discipline).
//! 2. Look up the declaration's `trust_root.root_key_id` in the
//!    operator's configured trust roots.
//! 3. Re-encode the canonical payload (sans signature) and verify
//!    the Ed25519 signature with domain separation
//!    `b"kryphocron/v1/service-trust-declaration/"` (the
//!    crate-internal `TRUST_DECLARATION_DOMAIN_TAG` constant).
//! 4. Validity-window enforcement: `iat` past with skew, `exp`
//!    future with skew, `exp - iat` ≤
//!    [`crate::trust::MAX_TRUST_DECLARATION_VALIDITY`].
//! 5. Construct [`crate::ingress::ServiceTrustDeclaration`] via the
//!    crate-internal constructor.

use core::marker::PhantomData;
use std::time::{Duration, SystemTime};

use ciborium::Value;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use thiserror::Error;

use crate::authority::capability::{CapabilityKind, CapabilitySet};
use crate::ingress::{ServiceTrustDeclaration, TrustDeclarationId};
use crate::identity::{KeyId, PublicKey, ServiceIdentity, SignatureAlgorithm};
use crate::proto::Did;
use crate::wire::ResourceScope;

/// Hard upper bound on a trust declaration's validity window
/// (§7.4).
///
/// 30 days. Longer-lived declarations are rejected at verification
/// time — the ceiling bounds the impact of a leaked declaration.
pub const MAX_TRUST_DECLARATION_VALIDITY: Duration =
    Duration::from_secs(30 * 86400);

/// Domain-separation tag for trust-declaration signatures (§7.4).
///
/// Distinct from [`crate::wire::CLAIM_DOMAIN_TAG`] (capability
/// claim) and from delegation-receipt / sync-handshake tags that
/// land in later sub-phases. Cross-domain signature reuse is
/// foreclosed by tag distinctness.
pub(crate) const TRUST_DECLARATION_DOMAIN_TAG: &[u8] =
    b"kryphocron/v1/service-trust-declaration/";

/// Operator-configured trust root (§7.4).
///
/// A trust-root identity is the (key id, public key) pair the
/// operator uses to sign trust declarations. Operators manage the
/// pre-shared list of acceptable trust roots out of band; the
/// substrate's verification path consults this list to look up the
/// signing key for a received declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustRootIdentity {
    /// Key id named in the declaration's `trust_root.root_key_id`.
    pub root_key_id: KeyId,
    /// Public-key material for signature verification.
    pub root_key: PublicKey,
}

/// Signature attesting to a trust declaration (§7.4).
///
/// Signed by a [`TrustRootIdentity`] over the deterministic-CBOR
/// encoding of the declaration's payload (sans this `signature`
/// field) with domain separation
/// `b"kryphocron/v1/service-trust-declaration/"` (the
/// crate-internal `TRUST_DECLARATION_DOMAIN_TAG` constant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustRootSignature {
    /// Algorithm under which `bytes` is interpreted.
    pub algorithm: SignatureAlgorithm,
    /// Raw signature bytes (Ed25519: 64 bytes).
    pub bytes: [u8; 64],
}

/// Trust-declaration verification failure (§7.4).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TrustDeclarationError {
    /// Declaration was structurally malformed: bad CBOR, missing
    /// field, type mismatch, or non-canonical encoding (the §7
    /// round-4 hazard).
    #[error("trust declaration malformed: {0}")]
    Malformed(String),
    /// Declaration cites a `trust_root.root_key_id` that is not
    /// in the operator's configured trust-roots list.
    #[error("trust declaration cites unknown trust root")]
    UnknownTrustRoot,
    /// Signature did not verify against the configured trust root.
    #[error("trust declaration signature invalid")]
    SignatureInvalid,
    /// Declaration has expired.
    #[error("trust declaration expired (exp={exp:?}, now={now:?})")]
    Expired {
        /// `expires_at` from the declaration.
        exp: SystemTime,
        /// Current time at verification.
        now: SystemTime,
    },
    /// Declaration is not yet valid (`issued_at` in the future
    /// beyond skew tolerance).
    #[error("trust declaration not yet valid")]
    NotYetValid {
        /// `issued_at` from the declaration.
        iat: SystemTime,
        /// Current time at verification.
        now: SystemTime,
        /// Clock skew tolerated.
        skew: Duration,
    },
    /// `expires_at - issued_at` exceeds
    /// [`MAX_TRUST_DECLARATION_VALIDITY`]. Implementation-derived
    /// addition for Phase 6 spec patch — §7.4's prose enumerates
    /// five variants but commits the 30-day ceiling, so the
    /// explicit error variant follows from enforcement.
    #[error("trust declaration validity window {window:?} exceeds max {max:?}")]
    ValidityWindowTooLong {
        /// Requested validity window.
        window: Duration,
        /// Maximum permitted.
        max: Duration,
    },
}

/// Verify a service trust declaration's wire bytes (§7.4).
///
/// `raw_bytes` is the deterministic-CBOR encoding of the full
/// declaration including its `signature` field. The verification
/// chain runs in §7.4's committed order:
///
/// 1. CBOR decode + round-trip canonicality check.
/// 2. Trust-root lookup.
/// 3. Domain-separated Ed25519 signature verification over the
///    canonical payload (sans signature).
/// 4. Validity window: `iat` past with skew, `exp` future with
///    skew, `exp - iat` ≤ [`MAX_TRUST_DECLARATION_VALIDITY`].
/// 5. Construct [`ServiceTrustDeclaration`] via the crate-internal
///    constructor.
///
/// On success returns [`ServiceTrustDeclaration`] — an
/// unforgeable token; consumers receiving one need not re-verify.
///
/// # Errors
///
/// Returns [`TrustDeclarationError`] on any failure. Each variant
/// is reachable independently from the verification chain.
pub fn verify_trust_declaration(
    raw_bytes: &[u8],
    configured_trust_roots: &[TrustRootIdentity],
    max_clock_skew: Duration,
    now: SystemTime,
) -> Result<ServiceTrustDeclaration, TrustDeclarationError> {
    // 1. CBOR decode + round-trip canonicality check (§7
    //    round-4 hazard foreclosure).
    let value = crate::wire::canonical_cbor_decode(raw_bytes)
        .map_err(|()| TrustDeclarationError::Malformed("CBOR decode".into()))?;
    let re_encoded = crate::wire::canonical_cbor_encode(value.clone());
    if re_encoded != raw_bytes {
        return Err(TrustDeclarationError::Malformed(
            "non-canonical CBOR encoding".into(),
        ));
    }

    // 2. Decode the declaration shape from the value tree.
    let parts = decode_declaration(&value)?;
    let DeclarationParts {
        declaration_id,
        from_service,
        to_service,
        capabilities,
        resource_scope,
        issued_at,
        expires_at,
        trust_root,
        signature,
    } = parts;

    // 3. Trust-root lookup against the operator's configured list.
    let configured = configured_trust_roots
        .iter()
        .find(|tr| tr.root_key_id == trust_root.root_key_id)
        .ok_or(TrustDeclarationError::UnknownTrustRoot)?;
    // The declaration's claimed root_key bytes must match the
    // operator's configured trust-root key bytes — otherwise an
    // attacker who knows the key id but not the key material
    // could substitute their own key.
    if configured.root_key.bytes != trust_root.root_key.bytes
        || configured.root_key.algorithm != trust_root.root_key.algorithm
    {
        return Err(TrustDeclarationError::UnknownTrustRoot);
    }

    // 4. Re-encode the canonical payload (sans signature) and
    //    verify the Ed25519 signature with domain separation.
    let canonical_payload = encode_canonical_payload(
        &declaration_id,
        &from_service,
        &to_service,
        &capabilities,
        &resource_scope,
        issued_at,
        expires_at,
        &trust_root,
    );
    let mut signing_input = Vec::with_capacity(
        TRUST_DECLARATION_DOMAIN_TAG.len() + canonical_payload.len(),
    );
    signing_input.extend_from_slice(TRUST_DECLARATION_DOMAIN_TAG);
    signing_input.extend_from_slice(&canonical_payload);
    verify_signature(&signing_input, &signature, &configured.root_key)?;

    // 5. Validity window: max validity, expiry, not-yet-valid.
    let window = expires_at
        .duration_since(issued_at)
        .unwrap_or(Duration::ZERO);
    if window > MAX_TRUST_DECLARATION_VALIDITY {
        return Err(TrustDeclarationError::ValidityWindowTooLong {
            window,
            max: MAX_TRUST_DECLARATION_VALIDITY,
        });
    }
    if now > expires_at + max_clock_skew {
        return Err(TrustDeclarationError::Expired {
            exp: expires_at,
            now,
        });
    }
    if now + max_clock_skew < issued_at {
        return Err(TrustDeclarationError::NotYetValid {
            iat: issued_at,
            now,
            skew: max_clock_skew,
        });
    }

    // 6. Construct ServiceTrustDeclaration.
    Ok(ServiceTrustDeclaration {
        declaration_id,
        from_service,
        to_service,
        capabilities,
        resource_scope,
        issued_at,
        expires_at,
        trust_root,
        signature,
        _private: PhantomData,
    })
}

/// Decoded declaration fields (intermediate representation
/// between CBOR `Value` tree and the final
/// [`ServiceTrustDeclaration`] type).
struct DeclarationParts {
    declaration_id: TrustDeclarationId,
    from_service: ServiceIdentity,
    to_service: ServiceIdentity,
    capabilities: CapabilitySet,
    resource_scope: ResourceScope,
    issued_at: SystemTime,
    expires_at: SystemTime,
    trust_root: TrustRootIdentity,
    signature: TrustRootSignature,
}

fn decode_declaration(value: &Value) -> Result<DeclarationParts, TrustDeclarationError> {
    let map = match value {
        Value::Map(entries) => entries,
        _ => return Err(TrustDeclarationError::Malformed("not a map".into())),
    };
    let get = |key: &str| -> Result<&Value, TrustDeclarationError> {
        map.iter()
            .find_map(|(k, v)| match k {
                Value::Text(s) if s == key => Some(v),
                _ => None,
            })
            .ok_or_else(|| TrustDeclarationError::Malformed(format!("missing field: {key}")))
    };

    let declaration_id = decode_declaration_id(get("declaration_id")?)?;
    let from_service = decode_service_identity(get("from_service")?)?;
    let to_service = decode_service_identity(get("to_service")?)?;
    let capabilities = decode_capabilities(get("capabilities")?)?;
    let resource_scope = decode_resource_scope(get("resource_scope")?)?;
    let issued_at = decode_system_time(get("issued_at")?)?;
    let expires_at = decode_system_time(get("expires_at")?)?;
    let trust_root = decode_trust_root(get("trust_root")?)?;
    let signature = decode_trust_root_signature(get("signature")?)?;

    Ok(DeclarationParts {
        declaration_id,
        from_service,
        to_service,
        capabilities,
        resource_scope,
        issued_at,
        expires_at,
        trust_root,
        signature,
    })
}

fn decode_declaration_id(v: &Value) -> Result<TrustDeclarationId, TrustDeclarationError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(TrustDeclarationError::Malformed("declaration_id not bytes".into())),
    };
    let arr: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustDeclarationError::Malformed("declaration_id wrong length".into()))?;
    Ok(TrustDeclarationId::from_bytes(arr))
}

fn decode_service_identity(v: &Value) -> Result<ServiceIdentity, TrustDeclarationError> {
    let map = match v {
        Value::Map(e) => e,
        _ => return Err(TrustDeclarationError::Malformed("service identity not a map".into())),
    };
    let get = |key: &str| -> Result<&Value, TrustDeclarationError> {
        map.iter()
            .find_map(|(k, val)| match k {
                Value::Text(s) if s == key => Some(val),
                _ => None,
            })
            .ok_or_else(|| {
                TrustDeclarationError::Malformed(format!("missing service identity field: {key}"))
            })
    };
    let did_str = match get("did")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(TrustDeclarationError::Malformed("did not text".into())),
    };
    let did = Did::new(did_str)
        .map_err(|_| TrustDeclarationError::Malformed("did invalid".into()))?;
    let key_id_bytes = match get("key_id")? {
        Value::Bytes(b) => b,
        _ => return Err(TrustDeclarationError::Malformed("key_id not bytes".into())),
    };
    let key_id_arr: [u8; 32] = key_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustDeclarationError::Malformed("key_id wrong length".into()))?;
    let key_alg_str = match get("key_alg")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(TrustDeclarationError::Malformed("key_alg not text".into())),
    };
    let algorithm = match key_alg_str {
        "Ed25519" => SignatureAlgorithm::Ed25519,
        "Es256" => SignatureAlgorithm::Es256,
        "Es256K" => SignatureAlgorithm::Es256K,
        _ => {
            return Err(TrustDeclarationError::Malformed(format!(
                "unknown signature algorithm: {key_alg_str}"
            )))
        }
    };
    let key_material_bytes = match get("key_material")? {
        Value::Bytes(b) => b,
        _ => {
            return Err(TrustDeclarationError::Malformed(
                "key_material not bytes".into(),
            ))
        }
    };
    let key_material_arr: [u8; 32] = key_material_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustDeclarationError::Malformed("key_material wrong length".into()))?;
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

fn decode_capabilities(v: &Value) -> Result<CapabilitySet, TrustDeclarationError> {
    let arr = match v {
        Value::Array(items) => items,
        _ => return Err(TrustDeclarationError::Malformed("capabilities not array".into())),
    };
    let mut kinds = Vec::with_capacity(arr.len());
    for item in arr {
        let name = match item {
            Value::Text(s) => s.as_str(),
            _ => {
                return Err(TrustDeclarationError::Malformed(
                    "capability not text".into(),
                ))
            }
        };
        let cap = CapabilityKind::from_wire_name(name).ok_or_else(|| {
            TrustDeclarationError::Malformed(format!("unknown capability: {name}"))
        })?;
        kinds.push(cap);
    }
    Ok(CapabilitySet::from_kinds(kinds))
}

fn decode_resource_scope(v: &Value) -> Result<ResourceScope, TrustDeclarationError> {
    let map = match v {
        Value::Map(e) => e,
        _ => return Err(TrustDeclarationError::Malformed("resource_scope not a map".into())),
    };
    let kind = map.iter().find_map(|(k, val)| match k {
        Value::Text(s) if s == "kind" => Some(val),
        _ => None,
    });
    let kind_str = match kind {
        Some(Value::Text(s)) => s.as_str(),
        _ => {
            return Err(TrustDeclarationError::Malformed(
                "resource_scope.kind missing or not text".into(),
            ))
        }
    };
    match kind_str {
        "class_wide_administrative" => Ok(ResourceScope::ClassWideAdministrative),
        "all_resources_owned_by" => {
            let value = map
                .iter()
                .find_map(|(k, val)| match k {
                    Value::Text(s) if s == "value" => Some(val),
                    _ => None,
                })
                .ok_or_else(|| {
                    TrustDeclarationError::Malformed("missing scope.value".into())
                })?;
            let did_str = match value {
                Value::Text(s) => s.as_str(),
                _ => {
                    return Err(TrustDeclarationError::Malformed(
                        "scope.value not text".into(),
                    ))
                }
            };
            let did = Did::new(did_str)
                .map_err(|_| TrustDeclarationError::Malformed("scope.value invalid did".into()))?;
            Ok(ResourceScope::AllResourcesOwnedBy(did))
        }
        // §7.4 trust declarations don't typically scope to single
        // resources (they're broader operator-level grants), but
        // the type is reachable for completeness.
        "resource" => Err(TrustDeclarationError::Malformed(
            "Resource scope not supported in trust declarations in 4c".into(),
        )),
        other => Err(TrustDeclarationError::Malformed(format!(
            "unknown resource_scope kind: {other}"
        ))),
    }
}

fn decode_system_time(v: &Value) -> Result<SystemTime, TrustDeclarationError> {
    match v {
        Value::Integer(i) => {
            let secs: u64 = (*i)
                .try_into()
                .map_err(|_| TrustDeclarationError::Malformed("time integer out of range".into()))?;
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        }
        _ => Err(TrustDeclarationError::Malformed("time field not integer".into())),
    }
}

fn decode_trust_root(v: &Value) -> Result<TrustRootIdentity, TrustDeclarationError> {
    let map = match v {
        Value::Map(e) => e,
        _ => return Err(TrustDeclarationError::Malformed("trust_root not a map".into())),
    };
    let get = |key: &str| -> Result<&Value, TrustDeclarationError> {
        map.iter()
            .find_map(|(k, val)| match k {
                Value::Text(s) if s == key => Some(val),
                _ => None,
            })
            .ok_or_else(|| {
                TrustDeclarationError::Malformed(format!(
                    "missing trust_root field: {key}"
                ))
            })
    };
    let key_id_bytes = match get("root_key_id")? {
        Value::Bytes(b) => b,
        _ => return Err(TrustDeclarationError::Malformed("root_key_id not bytes".into())),
    };
    let key_id_arr: [u8; 32] = key_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustDeclarationError::Malformed("root_key_id wrong length".into()))?;
    let key_alg_str = match get("root_key_alg")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(TrustDeclarationError::Malformed("root_key_alg not text".into())),
    };
    let algorithm = match key_alg_str {
        "Ed25519" => SignatureAlgorithm::Ed25519,
        "Es256" => SignatureAlgorithm::Es256,
        "Es256K" => SignatureAlgorithm::Es256K,
        _ => {
            return Err(TrustDeclarationError::Malformed(format!(
                "unknown root_key_alg: {key_alg_str}"
            )))
        }
    };
    let key_material_bytes = match get("root_key_material")? {
        Value::Bytes(b) => b,
        _ => {
            return Err(TrustDeclarationError::Malformed(
                "root_key_material not bytes".into(),
            ))
        }
    };
    let key_material_arr: [u8; 32] = key_material_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustDeclarationError::Malformed("root_key_material wrong length".into()))?;
    Ok(TrustRootIdentity {
        root_key_id: KeyId::from_bytes(key_id_arr),
        root_key: PublicKey {
            algorithm,
            bytes: key_material_arr,
        },
    })
}

fn decode_trust_root_signature(
    v: &Value,
) -> Result<TrustRootSignature, TrustDeclarationError> {
    let map = match v {
        Value::Map(e) => e,
        _ => return Err(TrustDeclarationError::Malformed("signature not a map".into())),
    };
    let get = |key: &str| -> Result<&Value, TrustDeclarationError> {
        map.iter()
            .find_map(|(k, val)| match k {
                Value::Text(s) if s == key => Some(val),
                _ => None,
            })
            .ok_or_else(|| {
                TrustDeclarationError::Malformed(format!("missing signature field: {key}"))
            })
    };
    let alg_str = match get("alg")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(TrustDeclarationError::Malformed("signature.alg not text".into())),
    };
    let algorithm = match alg_str {
        "Ed25519" => SignatureAlgorithm::Ed25519,
        "Es256" => SignatureAlgorithm::Es256,
        "Es256K" => SignatureAlgorithm::Es256K,
        _ => {
            return Err(TrustDeclarationError::Malformed(format!(
                "unknown signature alg: {alg_str}"
            )))
        }
    };
    let bytes = match get("bytes")? {
        Value::Bytes(b) => b,
        _ => return Err(TrustDeclarationError::Malformed("signature.bytes not bytes".into())),
    };
    let bytes_arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustDeclarationError::Malformed("signature.bytes wrong length".into()))?;
    Ok(TrustRootSignature {
        algorithm,
        bytes: bytes_arr,
    })
}

/// Encode a [`ServiceTrustDeclaration`] as wire-format CBOR
/// bytes (every field including the signature). Operators
/// minting declarations use this on the construction side; the
/// substrate uses it on the receive-side for the round-trip
/// canonicality check.
#[must_use]
pub fn encode_wire_bytes(declaration: &ServiceTrustDeclaration) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Text("declaration_id".into()),
            Value::Bytes(declaration.declaration_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("from_service".into()),
            service_identity_value(&declaration.from_service),
        ),
        (
            Value::Text("to_service".into()),
            service_identity_value(&declaration.to_service),
        ),
        (
            Value::Text("capabilities".into()),
            capabilities_value(&declaration.capabilities),
        ),
        (
            Value::Text("resource_scope".into()),
            resource_scope_value(&declaration.resource_scope),
        ),
        (
            Value::Text("issued_at".into()),
            system_time_value(declaration.issued_at),
        ),
        (
            Value::Text("expires_at".into()),
            system_time_value(declaration.expires_at),
        ),
        (
            Value::Text("trust_root".into()),
            trust_root_value(&declaration.trust_root),
        ),
        (
            Value::Text("signature".into()),
            trust_root_signature_value(&declaration.signature),
        ),
    ]);
    crate::wire::canonical_cbor_encode(map)
}

/// Encode the declaration's signed payload (every field except
/// `signature`). Used at signing time and at receive-side
/// signature verification.
#[allow(clippy::too_many_arguments)]
fn encode_canonical_payload(
    declaration_id: &TrustDeclarationId,
    from_service: &ServiceIdentity,
    to_service: &ServiceIdentity,
    capabilities: &CapabilitySet,
    resource_scope: &ResourceScope,
    issued_at: SystemTime,
    expires_at: SystemTime,
    trust_root: &TrustRootIdentity,
) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Text("declaration_id".into()),
            Value::Bytes(declaration_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("from_service".into()),
            service_identity_value(from_service),
        ),
        (
            Value::Text("to_service".into()),
            service_identity_value(to_service),
        ),
        (
            Value::Text("capabilities".into()),
            capabilities_value(capabilities),
        ),
        (
            Value::Text("resource_scope".into()),
            resource_scope_value(resource_scope),
        ),
        (Value::Text("issued_at".into()), system_time_value(issued_at)),
        (Value::Text("expires_at".into()), system_time_value(expires_at)),
        (
            Value::Text("trust_root".into()),
            trust_root_value(trust_root),
        ),
    ]);
    crate::wire::canonical_cbor_encode(map)
}

fn service_identity_value(s: &ServiceIdentity) -> Value {
    Value::Map(vec![
        (
            Value::Text("did".into()),
            Value::Text(s.service_did().as_str().to_string()),
        ),
        (
            Value::Text("key_id".into()),
            Value::Bytes(s.key_id().as_bytes().to_vec()),
        ),
        (
            Value::Text("key_alg".into()),
            Value::Text(signature_alg_name(s.key_material().algorithm).into()),
        ),
        (
            Value::Text("key_material".into()),
            Value::Bytes(s.key_material().bytes.to_vec()),
        ),
    ])
}

fn capabilities_value(set: &CapabilitySet) -> Value {
    Value::Array(
        set.kinds()
            .iter()
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
                    (
                        Value::Text("did".into()),
                        Value::Text(rid.did().as_str().to_string()),
                    ),
                    (
                        Value::Text("nsid".into()),
                        Value::Text(rid.nsid().as_str().to_string()),
                    ),
                    (
                        Value::Text("rkey".into()),
                        Value::Text(rid.rkey().as_str().to_string()),
                    ),
                ]),
            ),
        ]),
        ResourceScope::AllResourcesOwnedBy(did) => Value::Map(vec![
            (
                Value::Text("kind".into()),
                Value::Text("all_resources_owned_by".into()),
            ),
            (
                Value::Text("value".into()),
                Value::Text(did.as_str().to_string()),
            ),
        ]),
        ResourceScope::ClassWideAdministrative => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("class_wide_administrative".into()),
        )]),
    }
}

fn trust_root_value(tr: &TrustRootIdentity) -> Value {
    Value::Map(vec![
        (
            Value::Text("root_key_id".into()),
            Value::Bytes(tr.root_key_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("root_key_alg".into()),
            Value::Text(signature_alg_name(tr.root_key.algorithm).into()),
        ),
        (
            Value::Text("root_key_material".into()),
            Value::Bytes(tr.root_key.bytes.to_vec()),
        ),
    ])
}

fn trust_root_signature_value(sig: &TrustRootSignature) -> Value {
    Value::Map(vec![
        (
            Value::Text("alg".into()),
            Value::Text(signature_alg_name(sig.algorithm).into()),
        ),
        (Value::Text("bytes".into()), Value::Bytes(sig.bytes.to_vec())),
    ])
}

fn signature_alg_name(a: SignatureAlgorithm) -> &'static str {
    match a {
        SignatureAlgorithm::Ed25519 => "Ed25519",
        SignatureAlgorithm::Es256 => "Es256",
        SignatureAlgorithm::Es256K => "Es256K",
    }
}

fn system_time_value(t: SystemTime) -> Value {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH not supported")
        .as_secs();
    Value::Integer(secs.into())
}

fn verify_signature(
    signing_input: &[u8],
    signature: &TrustRootSignature,
    public_key: &PublicKey,
) -> Result<(), TrustDeclarationError> {
    match signature.algorithm {
        SignatureAlgorithm::Ed25519 => {
            let sig = Ed25519Signature::from_bytes(&signature.bytes);
            let key = VerifyingKey::from_bytes(&public_key.bytes)
                .map_err(|_| TrustDeclarationError::SignatureInvalid)?;
            key.verify(signing_input, &sig)
                .map_err(|_| TrustDeclarationError::SignatureInvalid)
        }
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es256K => {
            // Phase 4a chainlink #26: ECDSA primitives stub here
            // too. Trust declarations with ES256/ES256K signatures
            // surface as SignatureInvalid until the broader
            // ECDSA roll-out lands.
            Err(TrustDeclarationError::SignatureInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_root_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn fixed_trust_root() -> TrustRootIdentity {
        let signing = fixed_root_signing_key();
        TrustRootIdentity {
            root_key_id: KeyId::from_bytes([0xCA; 32]),
            root_key: PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: signing.verifying_key().to_bytes(),
            },
        }
    }

    fn fixed_service_identity(did: &str) -> ServiceIdentity {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        ServiceIdentity::new_internal(
            Did::new(did).unwrap(),
            KeyId::from_bytes([1; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: signing.verifying_key().to_bytes(),
            },
            None,
        )
    }

    /// Build an in-window, properly-signed declaration's wire
    /// bytes for the happy-path tests.
    fn build_signed_wire(
        issued_at: SystemTime,
        expires_at: SystemTime,
        trust_root: TrustRootIdentity,
    ) -> Vec<u8> {
        let payload_bytes = encode_canonical_payload(
            &TrustDeclarationId::from_bytes([0xDD; 16]),
            &fixed_service_identity("did:web:from.example"),
            &fixed_service_identity("did:web:to.example"),
            &CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]),
            &ResourceScope::ClassWideAdministrative,
            issued_at,
            expires_at,
            &trust_root,
        );
        let mut signing_input =
            Vec::with_capacity(TRUST_DECLARATION_DOMAIN_TAG.len() + payload_bytes.len());
        signing_input.extend_from_slice(TRUST_DECLARATION_DOMAIN_TAG);
        signing_input.extend_from_slice(&payload_bytes);
        let sig = fixed_root_signing_key().sign(&signing_input);
        let signature = TrustRootSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sig.to_bytes(),
        };
        let provisional = ServiceTrustDeclaration {
            declaration_id: TrustDeclarationId::from_bytes([0xDD; 16]),
            from_service: fixed_service_identity("did:web:from.example"),
            to_service: fixed_service_identity("did:web:to.example"),
            capabilities: CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]),
            resource_scope: ResourceScope::ClassWideAdministrative,
            issued_at,
            expires_at,
            trust_root,
            signature,
            _private: PhantomData,
        };
        encode_wire_bytes(&provisional)
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn max_trust_declaration_validity_pinned_at_30_days() {
        assert_eq!(
            MAX_TRUST_DECLARATION_VALIDITY,
            Duration::from_secs(30 * 86400)
        );
    }

    #[test]
    fn trust_declaration_domain_tag_pinned_per_7_4() {
        assert_eq!(
            TRUST_DECLARATION_DOMAIN_TAG,
            b"kryphocron/v1/service-trust-declaration/"
        );
    }

    #[test]
    fn happy_path_verifies_a_signed_declaration() {
        let trust_root = fixed_trust_root();
        let issued_at = now();
        let expires_at = issued_at + Duration::from_secs(86400);
        let wire = build_signed_wire(issued_at, expires_at, trust_root);
        let decl = verify_trust_declaration(
            &wire,
            &[trust_root],
            Duration::from_secs(30),
            now(),
        )
        .unwrap();
        assert_eq!(
            decl.declaration_id().as_bytes(),
            &[0xDD; 16],
        );
        assert_eq!(decl.expires_at(), expires_at);
    }

    #[test]
    fn unknown_trust_root_returns_unknown_trust_root() {
        let trust_root = fixed_trust_root();
        let other_root = TrustRootIdentity {
            root_key_id: KeyId::from_bytes([0x99; 32]),
            root_key: PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0; 32],
            },
        };
        let issued_at = now();
        let expires_at = issued_at + Duration::from_secs(60);
        let wire = build_signed_wire(issued_at, expires_at, trust_root);
        // Configured roots don't include the one that signed.
        let err =
            verify_trust_declaration(&wire, &[other_root], Duration::from_secs(30), now())
                .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::UnknownTrustRoot));
    }

    #[test]
    fn signature_invalid_returns_signature_invalid() {
        let trust_root = fixed_trust_root();
        let issued_at = now();
        let expires_at = issued_at + Duration::from_secs(60);
        let mut wire = build_signed_wire(issued_at, expires_at, trust_root);
        // Tamper the signature: locate the 64-byte signature head
        // (`0x58 0x40`) and zero the bytes that follow.
        let head = wire
            .windows(2)
            .position(|w| w == [0x58, 0x40])
            .expect("signature byte-string must be present");
        let sig_start = head + 2;
        for b in &mut wire[sig_start..sig_start + 64] {
            *b = 0;
        }
        let err =
            verify_trust_declaration(&wire, &[trust_root], Duration::from_secs(30), now())
                .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::SignatureInvalid));
    }

    #[test]
    fn expired_declaration_returns_expired() {
        let trust_root = fixed_trust_root();
        let issued_at = now() - Duration::from_secs(7200);
        let expires_at = issued_at + Duration::from_secs(60);
        let wire = build_signed_wire(issued_at, expires_at, trust_root);
        let err =
            verify_trust_declaration(&wire, &[trust_root], Duration::from_secs(30), now())
                .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::Expired { .. }));
    }

    #[test]
    fn future_dated_declaration_returns_not_yet_valid() {
        let trust_root = fixed_trust_root();
        let issued_at = now() + Duration::from_secs(3600);
        let expires_at = issued_at + Duration::from_secs(60);
        let wire = build_signed_wire(issued_at, expires_at, trust_root);
        let err =
            verify_trust_declaration(&wire, &[trust_root], Duration::from_secs(30), now())
                .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::NotYetValid { .. }));
    }

    #[test]
    fn over_max_validity_window_returns_validity_window_too_long() {
        let trust_root = fixed_trust_root();
        let issued_at = now();
        // 31 days vs 30-day cap.
        let expires_at = issued_at + Duration::from_secs(31 * 86400);
        let wire = build_signed_wire(issued_at, expires_at, trust_root);
        let err =
            verify_trust_declaration(&wire, &[trust_root], Duration::from_secs(30), now())
                .unwrap_err();
        assert!(matches!(
            err,
            TrustDeclarationError::ValidityWindowTooLong { .. }
        ));
    }

    #[test]
    fn malformed_cbor_returns_malformed() {
        let err = verify_trust_declaration(
            &[0xFF, 0xFF, 0xFF],
            &[fixed_trust_root()],
            Duration::from_secs(30),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::Malformed(_)));
    }

    #[test]
    fn non_canonical_cbor_returns_malformed() {
        // Hand-built non-canonical map (zebra before apple). Even
        // though it decodes, the round-trip canonicality check
        // catches it.
        let non_canonical: Vec<u8> = vec![
            0xA2, 0x65, 0x7A, 0x65, 0x62, 0x72, 0x61, 0x01, 0x65, 0x61, 0x70, 0x70,
            0x6C, 0x65, 0x02,
        ];
        let err = verify_trust_declaration(
            &non_canonical,
            &[fixed_trust_root()],
            Duration::from_secs(30),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::Malformed(_)));
    }

    /// §7.4 W8-equivalent domain-separation forgery: a signature
    /// computed without the trust-declaration domain tag must
    /// not verify. Cross-domain reuse (e.g., capability-claim
    /// signature replayed as trust-declaration) is structurally
    /// foreclosed.
    #[test]
    fn signature_without_domain_tag_fails_verification() {
        let trust_root = fixed_trust_root();
        let issued_at = now();
        let expires_at = issued_at + Duration::from_secs(86400);
        let payload_bytes = encode_canonical_payload(
            &TrustDeclarationId::from_bytes([0xDD; 16]),
            &fixed_service_identity("did:web:from.example"),
            &fixed_service_identity("did:web:to.example"),
            &CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]),
            &ResourceScope::ClassWideAdministrative,
            issued_at,
            expires_at,
            &trust_root,
        );
        // Sign WITHOUT the domain tag — capability-claim-style
        // signing input.
        let sig_no_tag = fixed_root_signing_key().sign(&payload_bytes);
        let signature = TrustRootSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sig_no_tag.to_bytes(),
        };
        let provisional = ServiceTrustDeclaration {
            declaration_id: TrustDeclarationId::from_bytes([0xDD; 16]),
            from_service: fixed_service_identity("did:web:from.example"),
            to_service: fixed_service_identity("did:web:to.example"),
            capabilities: CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]),
            resource_scope: ResourceScope::ClassWideAdministrative,
            issued_at,
            expires_at,
            trust_root,
            signature,
            _private: PhantomData,
        };
        let wire = encode_wire_bytes(&provisional);
        let err = verify_trust_declaration(
            &wire,
            &[trust_root],
            Duration::from_secs(30),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustDeclarationError::SignatureInvalid));
    }
}

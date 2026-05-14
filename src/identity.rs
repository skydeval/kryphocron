//! Identity types shared across §4 and §7.
//!
//! These are the **identifier and key-material** primitives the
//! substrate uses to name principals and bind cryptographic
//! material to them. They are crate-root re-exports so consumers
//! can refer to them without traversing submodule paths.
//!
//! Grouped here:
//!
//! - [`TraceId`] — 16-byte forensic correlation identifier (§4.2).
//! - [`KeyId`] — 32-byte opaque key identifier used across DID
//!   rotation history, capability-claim issuance, delegation
//!   receipts, and nonce tracking (§4.8).
//! - [`PublicKey`] — algorithm-tagged public key bytes (§4.8).
//! - [`SignatureAlgorithm`] — algorithm allowlist enum (§4.8,
//!   §7.2).
//! - [`ServiceIdentity`] — substrate-internal service principal
//!   identity with rotation evidence (§4.8).
//! - [`RotationChain`], [`RotationEntry`] — key rotation history
//!   (§4.8).
//! - [`SessionId`], [`SessionDigest`], [`CorrelationKey`] —
//!   audit-correlation primitives keyed off sync-channel sessions
//!   (§4.4).

use core::fmt;
use std::time::SystemTime;

use smallvec::SmallVec;

use crate::proto::Did;
use crate::sealed;

/// Cryptographically random forensic-correlation identifier.
///
/// 128-bit. Carried on every [`crate::AuthContext`], every
/// [`crate::audit`] event, every [`crate::wire::CapabilityClaim`].
/// Forensic correlation only; not a capability artifact (knowing
/// a [`TraceId`] does not authorize anything).
///
/// See §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId([u8; 16]);

impl TraceId {
    /// Construct a [`TraceId`] from raw bytes. Operators with
    /// existing correlation systems may construct ids from those
    /// systems' identifier shapes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        TraceId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// 32-byte opaque key identifier.
///
/// Used to name a specific signing key in:
///
/// - [`ServiceIdentity::key_id`] for substrate-internal service
///   principals.
/// - [`crate::wire::DelegationReceiptPayload::previous_key_id`] /
///   `recipient_key_id` for delegation-receipt canonicalization
///   (§4.8).
/// - [`crate::wire::NonceIssuerKey::key_id`] in the unified
///   nonce-tracker key tuple (§4.8 round-4 reshape).
///
/// The substrate does not commit how [`KeyId`] values are derived;
/// operators may use fingerprints, opaque random ids, or any
/// scheme that keeps ids stable per signing-key. §8.4 covers
/// operator latitude on key naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 32]);

impl KeyId {
    /// Construct a [`KeyId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Algorithm-tagged public key bytes.
///
/// §4.8 commits a 32-byte body (Ed25519 public-key size). When
/// other algorithm variants are added to [`SignatureAlgorithm`]
/// in the future, the shape of [`PublicKey`] may need to grow;
/// it is `#[non_exhaustive]` to leave room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PublicKey {
    /// Algorithm the key material is interpreted under.
    pub algorithm: SignatureAlgorithm,
    /// Raw key material (Ed25519: 32 bytes).
    pub bytes: [u8; 32],
}

/// Supported signature algorithms.
///
/// Per §7.2 the v1 default JWT allowlist is `Ed25519` only.
/// Operators federating with broader ATProto ecosystems opt into
/// ECDSA variants explicitly via
/// [`crate::verification::JwtVerificationConfig::accepted_algorithms`].
///
/// `Es256` and `Es256K` are recognized by the JWT parser and the
/// allowlist mechanism but Phase 4a does not ship the underlying
/// signature primitives — operators configuring them in
/// `accepted_algorithms` will see verification fail with
/// [`crate::verification::JwtVerificationError::UnsupportedAlgorithm`]
/// at the signature-dispatch step. A later sub-phase will add the
/// `p256` / `k256` crate dependencies; chainlinks track the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// Ed25519 (EdDSA over Curve25519). v1 default. JWT `alg`
    /// header value: `"EdDSA"` (RFC 8037).
    Ed25519,
    /// ECDSA over the NIST P-256 curve. JWT `alg` header value:
    /// `"ES256"`. Phase 4a recognizes the variant; signature
    /// verification stubs with `UnsupportedAlgorithm`.
    Es256,
    /// ECDSA over the secp256k1 curve. JWT `alg` header value:
    /// `"ES256K"`. Phase 4a recognizes the variant; signature
    /// verification stubs with `UnsupportedAlgorithm`.
    Es256K,
}

/// Substrate-internal service principal identity (§4.8).
///
/// Composed of a service DID, a specific signing-key id and
/// material, plus optional rotation evidence for historical
/// verification.
///
/// Construction is gated to the verification path: consumers
/// receive [`ServiceIdentity`] values from
/// [`crate::verification`] / [`crate::resolver`], not from
/// arbitrary user code, because the rotation-evidence chain has
/// integrity requirements.
#[derive(Debug, Clone)]
pub struct ServiceIdentity {
    service_did: Did,
    key_id: KeyId,
    key_material: PublicKey,
    rotation_evidence: Option<RotationChain>,
    _private: core::marker::PhantomData<sealed::Token>,
}

impl ServiceIdentity {
    /// Crate-internal constructor. Consumers receive
    /// [`ServiceIdentity`] values from verification paths; raw
    /// construction is not part of the public surface.
    #[must_use]
    pub(crate) fn new_internal(
        service_did: Did,
        key_id: KeyId,
        key_material: PublicKey,
        rotation_evidence: Option<RotationChain>,
    ) -> Self {
        ServiceIdentity {
            service_did,
            key_id,
            key_material,
            rotation_evidence,
            _private: core::marker::PhantomData,
        }
    }

    /// Borrow the service DID.
    #[must_use]
    pub fn service_did(&self) -> &Did {
        &self.service_did
    }

    /// Return the key id of the currently-active signing key.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Borrow the current signing-key material.
    #[must_use]
    pub fn key_material(&self) -> &PublicKey {
        &self.key_material
    }

    /// Borrow the rotation chain if the service has rotated keys.
    #[must_use]
    pub fn rotation_evidence(&self) -> Option<&RotationChain> {
        self.rotation_evidence.as_ref()
    }
}

impl PartialEq for ServiceIdentity {
    fn eq(&self, other: &Self) -> bool {
        // Two service identities are equal if they reference the
        // same DID and the same currently-active key id. Rotation
        // evidence is metadata; identity equality should hold
        // through rotation history extensions.
        self.service_did == other.service_did && self.key_id == other.key_id
    }
}

impl Eq for ServiceIdentity {}

impl core::hash::Hash for ServiceIdentity {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Hash agrees with PartialEq: only (did, key_id).
        self.service_did.hash(state);
        self.key_id.hash(state);
    }
}

/// Maximum entries in a [`RotationChain`] (§4.8).
pub const MAX_ROTATION_DEPTH: usize = 16;

// Module-internal alias to satisfy intra-doc-link references when
// the import is not in the same scope as the surrounding type.
// Removing this should produce an immediate compile-time warning.

/// Ordered record of a service principal's key rotations.
///
/// Each entry documents an old→new key transition with a
/// signature by the old key authorizing the new one. Verification
/// of historical delegation receipts walks the chain to confirm
/// the receipt's `previous_key_id` was authorized at the receipt's
/// `derived_at` instant (§4.8 rotation tolerance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationChain {
    entries: SmallVec<[RotationEntry; MAX_ROTATION_DEPTH]>,
}

impl RotationChain {
    /// Construct a [`RotationChain`] from an iterator of entries.
    /// Rejects chains exceeding the per-`MAX_ROTATION_DEPTH` cap.
    pub fn new<I: IntoIterator<Item = RotationEntry>>(
        entries: I,
    ) -> Result<Self, RotationChainError> {
        let mut sv = SmallVec::new();
        for entry in entries {
            if sv.len() >= MAX_ROTATION_DEPTH {
                return Err(RotationChainError::TooDeep {
                    max: MAX_ROTATION_DEPTH,
                });
            }
            sv.push(entry);
        }
        Ok(RotationChain { entries: sv })
    }

    /// Borrow the entries in rotation order (oldest → newest).
    #[must_use]
    pub fn entries(&self) -> &[RotationEntry] {
        &self.entries
    }
}

/// Error constructing a [`RotationChain`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RotationChainError {
    /// More entries than [`MAX_ROTATION_DEPTH`] were supplied.
    #[error("rotation chain exceeds MAX_ROTATION_DEPTH = {max}")]
    TooDeep {
        /// The hard limit.
        max: usize,
    },
}

/// One rotation step in a [`RotationChain`].
///
/// The `rotation_signature` is a signature by `old_key` over a
/// canonicalized rotation payload binding `new_key` and
/// `rotated_at`. The detailed wire shape of the signature payload
/// is committed in §7.3 and is not Phase 1 work; Phase 1 ships
/// the type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RotationEntry {
    /// The key being rotated out.
    pub old_key: PublicKey,
    /// The key being rotated in.
    pub new_key: PublicKey,
    /// Signature by `old_key` authorizing the rotation.
    pub rotation_signature: crate::wire::ClaimSignature,
    /// When the rotation became active.
    pub rotated_at: SystemTime,
}

/// 32-byte session identifier (§4.3 ChannelBinding, §7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Construct a [`SessionId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        SessionId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Keyed Blake3 digest of a [`SessionId`] (§4.4).
///
/// Stored in [`crate::target::StructuralRepresentation::Channel`]
/// so that routine operator audit reads do not reveal raw session
/// ids. Same session within a deployment hashes to the same
/// digest; different deployments use different correlation keys
/// to prevent cross-substrate correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionDigest([u8; 32]);

impl SessionDigest {
    /// Construct a [`SessionDigest`] from raw bytes.
    ///
    /// Phase 1 ships the type; the keyed-hash construction in
    /// [`SessionDigest::compute`] is stubbed until Phase 4 wires
    /// in the Blake3 dependency per §9.5.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        SessionDigest(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute a [`SessionDigest`] via keyed Blake3 over a session
    /// id under a deployment correlation key.
    ///
    /// Phase 1 stub. Phase 4 wires the keyed-hash construction
    /// against the Blake3 crate per §9.5's dependency posture.
    #[must_use]
    pub fn compute(_session_id: &SessionId, _correlation_key: &CorrelationKey) -> Self {
        // Phase 4 implementation: keyed Blake3 with domain separation
        // `b"kryphocron/v1/session-digest/"`.
        unimplemented!("§4.4 SessionDigest::compute: Phase 4 wires keyed Blake3");
    }
}

/// Per-deployment correlation key for [`SessionDigest`] (§4.4).
///
/// Operators rotate infrequently (e.g., yearly). Rotation
/// invalidates audit correlation across the rotation boundary;
/// that is the designed effect.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CorrelationKey([u8; 32]);

impl CorrelationKey {
    /// Construct a [`CorrelationKey`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        CorrelationKey(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Custom Debug that does not leak key material.
impl fmt::Debug for CorrelationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CorrelationKey").field("redacted", &true).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_id_round_trip() {
        let bytes = [0xAB; 16];
        let id = TraceId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn correlation_key_debug_does_not_leak() {
        let key = CorrelationKey::from_bytes([0xFF; 32]);
        let s = format!("{key:?}");
        assert!(!s.contains("FF"), "Debug must not leak bytes");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn max_rotation_depth_constant_is_16() {
        assert_eq!(MAX_ROTATION_DEPTH, 16);
    }
}

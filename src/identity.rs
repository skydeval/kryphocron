// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

impl PublicKey {
    /// Construct a [`PublicKey`] from an algorithm tag and raw
    /// key bytes.
    ///
    /// Operators implementing a [`crate::resolver::DidResolver`]
    /// build [`PublicKey`] values from upstream key material. The
    /// struct is [`#[non_exhaustive]`] so v0.2+ may add fields
    /// (e.g., curve parameters) when additional
    /// [`SignatureAlgorithm`] variants ship; consumers using this
    /// constructor will see additive changes as additive
    /// arguments.
    #[must_use]
    pub const fn new(algorithm: SignatureAlgorithm, bytes: [u8; 32]) -> Self {
        PublicKey { algorithm, bytes }
    }
}

/// Supported signature algorithms.
///
/// Per §7.2 the v1 default JWT allowlist is `Ed25519` only.
/// Operators federating with broader ATProto ecosystems opt into
/// ECDSA variants explicitly via
/// [`crate::verification::JwtVerificationConfig::accepted_algorithms`].
///
/// `Es256` and `Es256K` are recognized by the JWT parser and the
/// allowlist mechanism but v0.1 does not ship the underlying
/// signature primitives — operators configuring them in
/// `accepted_algorithms` will see verification fail with
/// [`crate::verification::JwtVerificationError::UnsupportedAlgorithm`]
/// at the signature-dispatch step. A future release will add the
/// `p256` / `k256` crate dependencies; tracked alongside the surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// Ed25519 (EdDSA over Curve25519). v1 default. JWT `alg`
    /// header value: `"EdDSA"` (RFC 8037).
    Ed25519,
    /// ECDSA over the NIST P-256 curve. JWT `alg` header value:
    /// `"ES256"`. The variant is recognized; signature
    /// verification stubs with `UnsupportedAlgorithm` in v0.1.
    Es256,
    /// ECDSA over the secp256k1 curve. JWT `alg` header value:
    /// `"ES256K"`. The variant is recognized; signature
    /// verification stubs with `UnsupportedAlgorithm` in v0.1.
    Es256K,
}

/// External-issuer public key for JWT signature verification.
///
/// Distinct from the substrate-internal [`PublicKey`] (which is a fixed
/// `[u8; 32]` Ed25519 body encoded into the §4.8 capability-claim and §7.5
/// sync-handshake wire formats at that fixed width). `IssuerPublicKey` carries
/// the variable-width ECDSA keys real ATProto issuers use — secp256k1 (ES256K,
/// the did:plc canonical curve) and P-256 (ES256) — alongside Ed25519, sized
/// per-algorithm.
///
/// Used in [`crate::resolver::DidDocument::verification_methods`] and consumed
/// by the JWT signature verifier. It never enters the substrate's internal key
/// path or either wire format: the capability-claim / sync-handshake verifiers
/// extract a substrate [`PublicKey`] from the `Ed25519` variant at their
/// selector boundary (substrate service keys are always Ed25519), so the wire
/// formats stay byte-identical.
///
/// `#[non_exhaustive]` reserves room for future algorithms without breaking
/// external matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IssuerPublicKey {
    /// Ed25519 key — 32 raw bytes.
    Ed25519([u8; 32]),
    /// secp256k1 (ES256K) key — SEC1-encoded, compressed (33) or uncompressed
    /// (65) accepted, stored as received.
    Secp256k1(Vec<u8>),
    /// P-256 (ES256) key — SEC1-encoded, compressed (33) or uncompressed (65)
    /// accepted, stored as received.
    P256(Vec<u8>),
}

impl IssuerPublicKey {
    /// The signing algorithm this key material is interpreted under.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
            Self::Secp256k1(_) => SignatureAlgorithm::Es256K,
            Self::P256(_) => SignatureAlgorithm::Es256,
        }
    }

    /// The raw key bytes — Ed25519 is 32 raw bytes; ECDSA variants are SEC1.
    /// The caller interprets them per [`algorithm`](Self::algorithm).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(b) => b.as_slice(),
            Self::Secp256k1(b) | Self::P256(b) => b.as_slice(),
        }
    }
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
        }
    }

    /// Construct a service identity from its components.
    ///
    /// The primary consumer use is building an operator's **own** service
    /// audience identity at startup, to pass as `verify_jwt`'s
    /// `local_audience`: the receive-time audience check compares the JWT's
    /// `aud` against this identity's [`service_did`](Self::service_did).
    /// `rotation_evidence` is `None` for a fresh service with no prior key
    /// rotation.
    #[must_use]
    pub fn new(
        service_did: Did,
        key_id: KeyId,
        key_material: PublicKey,
        rotation_evidence: Option<RotationChain>,
    ) -> Self {
        Self::new_internal(service_did, key_id, key_material, rotation_evidence)
    }

    /// Test-support constructor. Available only with the
    /// `test-support` feature enabled.
    ///
    /// Builds a [`ServiceIdentity`] from raw components, bypassing
    /// the verification path. Reserved for out-of-crate
    /// integration tests that need to construct a
    /// [`crate::Requester::Service`] without standing up the full
    /// capability-claim verification surface.
    ///
    /// See [`crate::AuthContext::new_for_test`] for the matching
    /// caveat: do not enable the `test-support` feature in
    /// non-test builds.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn new_for_test(
        service_did: Did,
        key_id: KeyId,
        key_material: PublicKey,
        rotation_evidence: Option<RotationChain>,
    ) -> Self {
        Self::new_internal(service_did, key_id, key_material, rotation_evidence)
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
/// is committed in §7.3; v0.1 ships the type vocabulary.
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
    /// Operators typically construct digests via
    /// [`SessionDigest::compute`] (keyed Blake3 over the session
    /// id under the deployment correlation key); this constructor
    /// is for round-tripping persisted digests or for testing.
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
    /// Construction (§4.4 + §7.5):
    /// `blake3::keyed_hash(correlation_key.as_bytes(), session_id.as_bytes())`.
    ///
    /// The 32-byte Blake3 keyed-hash output is the digest. Same
    /// session within a deployment hashes to the same digest;
    /// different deployments configured with different
    /// [`CorrelationKey`] values produce non-correlatable digests
    /// for the same session id, which is the deliberate cross-
    /// deployment isolation property §4.4 commits to.
    #[must_use]
    pub fn compute(session_id: &SessionId, correlation_key: &CorrelationKey) -> Self {
        let hash = blake3::keyed_hash(correlation_key.as_bytes(), session_id.as_bytes());
        SessionDigest(*hash.as_bytes())
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

/// Per-substrate-instance Blake3 keying material for session-id
/// derivation (§7.5).
///
/// 256-bit. Generated at substrate startup, never persisted across
/// restarts. Used to key the
/// [`derive_session_id`](crate::wire::derive_session_id)
/// construction:
///
/// ```text
/// session_id = blake3::keyed(
///     key   = SubstrateSessionDerivationKey,
///     input = proposed_session_nonce || responder_entropy,
/// )
/// ```
///
/// **Properties §7.5 commits.** A keyed-hash construction with this
/// per-instance key gives:
///
/// - Cross-substrate session-ID predictability is foreclosed: an
///   attacker observing session ids from one substrate instance
///   cannot predict session ids from another instance.
/// - Within an instance, session-id uniqueness across distinct
///   `(nonce, entropy)` pairs follows from the keyed Blake3 PRF
///   property.
///
/// **Operator discipline §7.5 does not enforce in safe Rust.** The
/// "never persisted" property is operator policy, not a type-system
/// invariant. The constructor surface (`generate` plus
/// `from_bytes`) supports both common shapes:
///
/// - `generate()` for the default startup pattern (uses the system
///   RNG via the Blake3 crate's transitive dependency on
///   `getrandom`).
/// - `from_bytes()` for HSM-backed deployments where the key
///   material is held in operator-controlled secure storage and
///   passed in at startup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SubstrateSessionDerivationKey([u8; 32]);

impl SubstrateSessionDerivationKey {
    /// Construct a [`SubstrateSessionDerivationKey`] from raw
    /// bytes. Operators with HSM-backed key storage supply key
    /// material via this path.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        SubstrateSessionDerivationKey(bytes)
    }

    /// Generate fresh keying material from the operating-system
    /// CSPRNG. Use at substrate startup unless operator policy
    /// dictates HSM-supplied key material.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        // `getrandom` is in the dep tree transitively (via
        // ed25519-dalek and blake3). Unwrap is acceptable: a system
        // RNG failure at substrate startup is unrecoverable for any
        // signature-based service.
        getrandom::getrandom(&mut bytes)
            .expect("OS CSPRNG must be available at substrate startup");
        SubstrateSessionDerivationKey(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Custom Debug that does not leak key material.
impl fmt::Debug for SubstrateSessionDerivationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubstrateSessionDerivationKey")
            .field("redacted", &true)
            .finish()
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

    /// `SubstrateSessionDerivationKey::generate` produces fresh,
    /// non-zero key material each call. Sanity check on the OS
    /// CSPRNG path: two consecutive generations should not collide
    /// (Birthday bound on 256-bit output makes any collision a
    /// hard-test failure to investigate).
    #[test]
    fn substrate_session_derivation_key_generate_produces_distinct_keys() {
        let k1 = SubstrateSessionDerivationKey::generate();
        let k2 = SubstrateSessionDerivationKey::generate();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// Debug must not leak key bytes for the session-derivation
    /// key (mirrors [`CorrelationKey`]'s redaction discipline).
    #[test]
    fn substrate_session_derivation_key_debug_does_not_leak() {
        let key = SubstrateSessionDerivationKey::from_bytes([0xCC; 32]);
        let s = format!("{key:?}");
        assert!(!s.contains("CC"), "Debug must not leak key bytes");
        assert!(s.contains("redacted"));
    }

    /// `SessionDigest::compute` produces the same digest for the
    /// same `(session_id, correlation_key)` and different digests
    /// for different correlation keys (cross-deployment isolation
    /// per §4.4).
    #[test]
    fn session_digest_compute_is_deterministic_and_key_separated() {
        let session = SessionId::from_bytes([0xAB; 32]);
        let key_a = CorrelationKey::from_bytes([0x11; 32]);
        let key_b = CorrelationKey::from_bytes([0x22; 32]);

        let d_a1 = SessionDigest::compute(&session, &key_a);
        let d_a2 = SessionDigest::compute(&session, &key_a);
        let d_b = SessionDigest::compute(&session, &key_b);

        assert_eq!(d_a1, d_a2, "deterministic for the same key");
        assert_ne!(
            d_a1, d_b,
            "different keys must produce non-correlatable digests"
        );
    }

    /// `SessionDigest::compute` separates by session id: same key,
    /// different sessions yield different digests (Blake3 PRF
    /// property).
    #[test]
    fn session_digest_compute_separates_by_session() {
        let key = CorrelationKey::from_bytes([0x33; 32]);
        let s1 = SessionId::from_bytes([0x44; 32]);
        let s2 = SessionId::from_bytes([0x45; 32]);

        let d1 = SessionDigest::compute(&s1, &key);
        let d2 = SessionDigest::compute(&s2, &key);

        assert_ne!(d1, d2);
    }
}

/// Test-support signing fixtures for ES256K / ES256 (and Ed25519) JWTs.
///
/// Exposed under the `test-support` feature so downstream crates can build
/// signed-JWT happy-path fixtures against the new ECDSA verifiers without
/// hand-rolling JWS signing. §0.4 keeps `test-support` compile-excluded from
/// release builds; enable it only in `[dev-dependencies]`.
#[cfg(feature = "test-support")]
pub mod fixtures {
    use super::IssuerPublicKey;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    /// Deterministic secp256k1 signing key + matching `IssuerPublicKey`
    /// (compressed SEC1), seed-driven for reproducible tests.
    #[must_use]
    pub fn secp256k1_signing_pair(seed: [u8; 32]) -> (k256::ecdsa::SigningKey, IssuerPublicKey) {
        let sk = k256::ecdsa::SigningKey::from_slice(&seed).expect("valid secp256k1 seed");
        let pk = IssuerPublicKey::Secp256k1(
            sk.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
        );
        (sk, pk)
    }

    /// Deterministic P-256 signing key + matching `IssuerPublicKey` (compressed
    /// SEC1).
    #[must_use]
    pub fn p256_signing_pair(seed: [u8; 32]) -> (p256::ecdsa::SigningKey, IssuerPublicKey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&seed).expect("valid p256 seed");
        let pk = IssuerPublicKey::P256(
            sk.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
        );
        (sk, pk)
    }

    /// Build the JWS signing input `b64url(header).b64url(payload)`.
    fn jws_signing_input(header: &serde_json::Value, payload: &serde_json::Value) -> String {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header JSON")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("payload JSON")),
        )
    }

    /// Sign a JWT with ES256K (secp256k1). Returns the compact JWS string. The
    /// signature is low-S normalized (ATProto canonical) and fixed `r‖s`.
    #[must_use]
    pub fn sign_jwt_es256k(
        header: &serde_json::Value,
        payload: &serde_json::Value,
        signing_key: &k256::ecdsa::SigningKey,
    ) -> String {
        use k256::ecdsa::{signature::Signer, Signature};
        let signing_input = jws_signing_input(header, payload);
        let sig: Signature = signing_key.sign(signing_input.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    /// Sign a JWT with ES256 (P-256). See [`sign_jwt_es256k`].
    #[must_use]
    pub fn sign_jwt_es256(
        header: &serde_json::Value,
        payload: &serde_json::Value,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> String {
        use p256::ecdsa::{signature::Signer, Signature};
        let signing_input = jws_signing_input(header, payload);
        let sig: Signature = signing_key.sign(signing_input.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

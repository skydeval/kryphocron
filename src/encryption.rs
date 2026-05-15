//! §8 encryption-hook surfaces — **type vocabulary only**.
//!
//! Phase 1 ships the opaque key-id types
//! ([`AuditEncryptionKeyId`], [`RecordEncryptionKeyId`]) and the
//! empty algorithm enums ([`AuditEncryptionAlgorithm`],
//! [`RecordEncryptionAlgorithm`]) per §8.5's commitment.
//!
//! The hook traits (`AuditEncryptionResolver`,
//! `RecordEncryptionResolver`, `EncryptionResolverSet`) and the
//! context structs are committed as **surface-only** placeholders
//! here so the §4.4 [`SensitiveRepresentation`] type and the §4.9
//! audit pipeline can refer to them. Phase 5 implements the trait
//! surfaces in full; v1 ships no concrete resolver implementations.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use smallvec::SmallVec;
use thiserror::Error;

use crate::authority::CapabilityKind;
use crate::identity::TraceId;
use crate::proto::{AtUri, Did, Nsid};
use crate::target::SensitiveRepresentation;

/// 32-byte opaque audit-encryption key identifier (§8.2).
///
/// The substrate does not interpret the bytes; operator
/// [`AuditEncryptionResolver`] implementations resolve them to
/// key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditEncryptionKeyId([u8; 32]);

impl AuditEncryptionKeyId {
    /// Construct an [`AuditEncryptionKeyId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        AuditEncryptionKeyId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 32-byte opaque record-encryption key identifier (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordEncryptionKeyId([u8; 32]);

impl RecordEncryptionKeyId {
    /// Construct a [`RecordEncryptionKeyId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        RecordEncryptionKeyId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Algorithm tag for audit-encryption ciphertexts (§8.2).
///
/// **v1 ships no variants.** Future versions add variants like
/// `Aes256Gcm`, `ChaCha20Poly1305`; the enum is
/// `#[non_exhaustive]` from day one so additions are
/// backward-compatible.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditEncryptionAlgorithm {}

/// Algorithm tag for record-encryption ciphertexts (§8.3).
///
/// **v1 ships no variants.** Same discipline as
/// [`AuditEncryptionAlgorithm`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordEncryptionAlgorithm {}

/// Encryption-operation context handed to
/// [`AuditEncryptionResolver`] implementations.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct EncryptionContext {
    /// The capability that triggered the encrypted emission.
    pub capability: CapabilityKind,
    /// The trace id correlating to the emission's audit event.
    pub trace_id: TraceId,
    /// Operator-extensible context; the substrate does not
    /// interpret these fields.
    pub operator_context: SmallVec<[(String, Vec<u8>); 2]>,
}

/// Encryption-operation context handed to
/// [`RecordEncryptionResolver`] implementations.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RecordEncryptionContext {
    /// NSID of the record being encrypted.
    pub nsid: Nsid,
    /// DID of the record's originator.
    pub originator: Did,
    /// Audience-list reference, where applicable.
    pub audience_list: Option<AtUri>,
    /// Trace id correlating to the originating request.
    pub trace_id: TraceId,
    /// Operator-extensible context.
    pub operator_context: SmallVec<[(String, Vec<u8>); 2]>,
}

/// Encrypted record payload as written to storage (§8.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRecord {
    /// Key id used to encrypt.
    pub key_id: RecordEncryptionKeyId,
    /// Algorithm under which `ciphertext` is interpreted.
    pub algorithm: RecordEncryptionAlgorithm,
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// Additional authenticated data; substrate-defined fields
    /// the encryption binds to without including in ciphertext.
    /// v1 commits the field; v2 commits which substrate fields
    /// are bound (§8.3).
    pub aad: Vec<u8>,
}

/// Failure cases for both encryption surfaces (§8.2, §8.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncryptionError {
    /// Key id did not resolve.
    #[error("encryption key not found: {key_id:?}")]
    KeyNotFound {
        /// The key id that did not resolve.
        key_id: AuditEncryptionKeyId,
    },
    /// Algorithm not in the resolver's allowlist.
    #[error("encryption algorithm not supported: {0:?}")]
    AlgorithmNotSupported(AuditEncryptionAlgorithm),
    /// Ciphertext or payload was structurally malformed.
    #[error("encryption payload malformed")]
    Malformed,
    /// Resolver enforced access control beyond the substrate's
    /// privilege model.
    #[error("encryption access denied: {reason}")]
    AccessDenied {
        /// Operator-defined reason string.
        reason: &'static str,
    },
    /// Operation exceeded the supplied deadline.
    #[error("encryption deadline exceeded after {elapsed:?}")]
    DeadlineExceeded {
        /// How long the operation ran before the deadline check fired.
        elapsed: Duration,
    },
    /// Upstream KMS or signing infrastructure failed.
    #[error("encryption upstream error: {0}")]
    UpstreamError(String),
}

/// Resolves audit-encryption key ids to key material and
/// performs encrypt/decrypt on audit-event sensitive layers
/// (§8.2).
///
/// **Phase 1 ships the trait surface only.** v1 has no default
/// implementation; substrates configured without a resolver emit
/// audit events with [`crate::target::TargetRepresentation::sensitive`]
/// = `None`.
#[async_trait]
pub trait AuditEncryptionResolver: Send + Sync {
    /// Encrypt a plaintext payload.
    async fn encrypt(
        &self,
        plaintext: &[u8],
        context: &EncryptionContext,
        deadline: Instant,
    ) -> Result<SensitiveRepresentation, EncryptionError>;

    /// Decrypt a sensitive representation. Forensic readers with
    /// appropriate privilege call this; operator-implemented
    /// resolvers MAY enforce access control beyond the substrate's
    /// audit-sink privilege model.
    async fn decrypt(
        &self,
        sensitive: &SensitiveRepresentation,
        context: &EncryptionContext,
        deadline: Instant,
    ) -> Result<Vec<u8>, EncryptionError>;

    /// The currently active key id for emission.
    fn active_key_id(&self) -> AuditEncryptionKeyId;
}

/// Resolves record-encryption key ids and performs
/// encrypt/decrypt on record content at rest (§8.3).
#[async_trait]
pub trait RecordEncryptionResolver: Send + Sync {
    /// Encrypt record content.
    async fn encrypt_record(
        &self,
        plaintext: &[u8],
        context: &RecordEncryptionContext,
        deadline: Instant,
    ) -> Result<EncryptedRecord, EncryptionError>;

    /// Decrypt record content for an authorized reader. The
    /// substrate's audience-check pipeline (§4.3 stages 2-3) has
    /// already verified the reader is authorized before this hook
    /// fires.
    async fn decrypt_record(
        &self,
        encrypted: &EncryptedRecord,
        reader: &Did,
        context: &RecordEncryptionContext,
        deadline: Instant,
    ) -> Result<Vec<u8>, EncryptionError>;
}

/// Set of installed encryption resolvers (§8.4).
///
/// Operators configure the resolver set at substrate startup;
/// both methods return `None` when no resolver is installed
/// (v1 default per §8.5).
pub trait EncryptionResolverSet: Send + Sync {
    /// Audit-encryption resolver, if installed.
    fn audit(&self) -> Option<Arc<dyn AuditEncryptionResolver>>;
    /// Record-encryption resolver, if installed.
    fn record(&self) -> Option<Arc<dyn RecordEncryptionResolver>>;
}

/// **v1 default** [`EncryptionResolverSet`] implementation that
/// returns `None` from both methods (§8.5).
///
/// Substrates configured with [`NoEncryption`] emit audit events
/// with [`crate::target::TargetRepresentation::sensitive`] = `None`
/// and store records as plaintext. This is the v1 baseline:
/// operators wanting at-rest encryption ship their own
/// [`EncryptionResolverSet`] implementation wrapping their
/// audit and / or record resolvers.
///
/// The struct is zero-sized; `NoEncryption` instances are free.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoEncryption;

impl EncryptionResolverSet for NoEncryption {
    fn audit(&self) -> Option<Arc<dyn AuditEncryptionResolver>> {
        None
    }
    fn record(&self) -> Option<Arc<dyn RecordEncryptionResolver>> {
        None
    }
}

// ============================================================
// §8.4 audit-emission integration helper.
// ============================================================

/// Audit-emission integration helper (§8.4): produce a
/// [`SensitiveRepresentation`] from `plaintext` using the
/// installed audit resolver, OR return `None` when no resolver
/// is installed.
///
/// Substrate components emitting audit events with sensitive
/// data call this helper. The returned `Option` flows directly
/// into [`crate::target::TargetRepresentation::sensitive`]:
///
/// ```text
/// let sensitive = produce_sensitive_representation(
///     plaintext_bytes,
///     &EncryptionContext { capability, trace_id, operator_context },
///     deadline,
///     resolver_set.audit().as_deref(),
/// ).await?;
/// let target = TargetRepresentation { structural, sensitive };
/// ```
///
/// **Errors propagate.** A resolver-side encryption failure
/// surfaces as [`EncryptionError`]; the substrate's audit-emit
/// path treats this as a hard failure (audit unavailability)
/// rather than silently dropping the sensitive layer. §4.9
/// commits the audit-unavailable bind-failure semantics.
///
/// # Errors
///
/// Returns [`EncryptionError`] from the resolver. When
/// `resolver` is `None`, returns `Ok(None)` unconditionally.
pub async fn produce_sensitive_representation(
    plaintext: &[u8],
    context: &EncryptionContext,
    deadline: Instant,
    resolver: Option<&dyn AuditEncryptionResolver>,
) -> Result<Option<SensitiveRepresentation>, EncryptionError> {
    match resolver {
        None => Ok(None),
        Some(r) => r.encrypt(plaintext, context, deadline).await.map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_enums_have_zero_v1_variants() {
        // §8.5 explicitly commits: "v1 ships no algorithm variants."
        // This pins that — adding a variant in v1 would be a
        // commitment-breaking change requiring §8 revision.
        //
        // We can't `match` over zero variants directly, but we can
        // confirm the type exists and is constructible only by
        // exhaustively-not-possible means.
        fn _assert_audit_alg_zero_variants(a: AuditEncryptionAlgorithm) -> ! {
            match a {}
        }
        fn _assert_record_alg_zero_variants(a: RecordEncryptionAlgorithm) -> ! {
            match a {}
        }
    }

    #[test]
    fn key_id_bytes_round_trip() {
        let bytes = [0xCC; 32];
        assert_eq!(AuditEncryptionKeyId::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(RecordEncryptionKeyId::from_bytes(bytes).as_bytes(), &bytes);
    }

    /// `NoEncryption` returns `None` from both `audit()` and
    /// `record()` per §8.5's v1 default.
    #[test]
    fn no_encryption_returns_none_from_both_methods() {
        let set = NoEncryption;
        assert!(set.audit().is_none());
        assert!(set.record().is_none());
    }

    /// `NoEncryption` is zero-sized — operators get the v1
    /// default with no allocation cost.
    #[test]
    fn no_encryption_is_zero_sized() {
        assert_eq!(std::mem::size_of::<NoEncryption>(), 0);
    }

    /// `EncryptionError` variant reachability — five of six
    /// variants are constructible in v1. The sixth
    /// (`AlgorithmNotSupported`) requires an
    /// [`AuditEncryptionAlgorithm`] value, and the algorithm
    /// enum is intentionally zero-variant in v1 (§8.5). The
    /// variant exists in the type surface but cannot be
    /// constructed until v1.x or v2 ships algorithm variants.
    #[test]
    fn encryption_error_constructible_variants_round_trip() {
        let _v1 = EncryptionError::KeyNotFound {
            key_id: AuditEncryptionKeyId::from_bytes([0; 32]),
        };
        let _v2 = EncryptionError::Malformed;
        let _v3 = EncryptionError::AccessDenied {
            reason: "test-only",
        };
        let _v4 = EncryptionError::DeadlineExceeded {
            elapsed: Duration::from_secs(1),
        };
        let _v5 = EncryptionError::UpstreamError("kms unreachable".into());
        // AlgorithmNotSupported(AuditEncryptionAlgorithm) is
        // structurally present but uninhabited in v1; this is
        // the §8.5 door-open posture.
    }

    /// `produce_sensitive_representation` returns `Ok(None)`
    /// when no resolver is installed (the §8.4 default path).
    #[tokio::test]
    async fn produce_sensitive_returns_none_when_resolver_absent() {
        let context = EncryptionContext {
            capability: CapabilityKind::ViewPrivate,
            trace_id: TraceId::from_bytes([0; 16]),
            operator_context: SmallVec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let result = produce_sensitive_representation(
            b"plaintext",
            &context,
            deadline,
            None,
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }

    /// Mock [`AuditEncryptionResolver`] impl confirming the
    /// trait is implementable in v1. The mock can return
    /// [`EncryptionError`] error variants but cannot construct
    /// a real [`SensitiveRepresentation`] — the
    /// `SensitiveRepresentation::algorithm` field requires an
    /// [`AuditEncryptionAlgorithm`] value, and the algorithm
    /// enum is uninhabited in v1 (§8.5). Operators implementing
    /// the trait in v1 can wire the surface but cannot return a
    /// real ciphertext until algorithm variants ship — the
    /// strict door-open posture.
    struct AlwaysAccessDenied;

    #[async_trait]
    impl AuditEncryptionResolver for AlwaysAccessDenied {
        async fn encrypt(
            &self,
            _plaintext: &[u8],
            _context: &EncryptionContext,
            _deadline: Instant,
        ) -> Result<SensitiveRepresentation, EncryptionError> {
            Err(EncryptionError::AccessDenied {
                reason: "mock resolver: always denies",
            })
        }
        async fn decrypt(
            &self,
            _sensitive: &SensitiveRepresentation,
            _context: &EncryptionContext,
            _deadline: Instant,
        ) -> Result<Vec<u8>, EncryptionError> {
            Err(EncryptionError::AccessDenied {
                reason: "mock resolver: always denies",
            })
        }
        fn active_key_id(&self) -> AuditEncryptionKeyId {
            AuditEncryptionKeyId::from_bytes([0xFF; 32])
        }
    }

    /// `produce_sensitive_representation` propagates resolver
    /// errors as `EncryptionError`. The mock returns
    /// `AccessDenied`; the helper returns it verbatim rather
    /// than translating or swallowing.
    #[tokio::test]
    async fn produce_sensitive_propagates_resolver_error() {
        let context = EncryptionContext {
            capability: CapabilityKind::ViewPrivate,
            trace_id: TraceId::from_bytes([0; 16]),
            operator_context: SmallVec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let resolver = AlwaysAccessDenied;
        let err = produce_sensitive_representation(
            b"plaintext",
            &context,
            deadline,
            Some(&resolver as &dyn AuditEncryptionResolver),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            EncryptionError::AccessDenied {
                reason: "mock resolver: always denies",
            }
        ));
    }

    /// Mock [`AuditEncryptionResolver`]'s `active_key_id`
    /// accessor returns the configured id.
    #[test]
    fn mock_audit_resolver_active_key_id_round_trips() {
        let resolver = AlwaysAccessDenied;
        assert_eq!(resolver.active_key_id().as_bytes(), &[0xFF; 32]);
    }

    /// Mock [`RecordEncryptionResolver`] impl confirming the
    /// record-side trait is implementable. Same v1 caveat as
    /// the audit-side mock — the [`EncryptedRecord::algorithm`]
    /// field requires a [`RecordEncryptionAlgorithm`] value,
    /// uninhabited in v1.
    struct AlwaysMalformedRecord;

    #[async_trait]
    impl RecordEncryptionResolver for AlwaysMalformedRecord {
        async fn encrypt_record(
            &self,
            _plaintext: &[u8],
            _context: &RecordEncryptionContext,
            _deadline: Instant,
        ) -> Result<EncryptedRecord, EncryptionError> {
            Err(EncryptionError::Malformed)
        }
        async fn decrypt_record(
            &self,
            _encrypted: &EncryptedRecord,
            _reader: &Did,
            _context: &RecordEncryptionContext,
            _deadline: Instant,
        ) -> Result<Vec<u8>, EncryptionError> {
            Err(EncryptionError::Malformed)
        }
    }

    /// Mock record-resolver compiles + can be invoked, returning
    /// `Malformed` on both encrypt and decrypt paths.
    #[tokio::test]
    async fn mock_record_resolver_returns_malformed() {
        let nsid = Nsid::new("tools.kryphocron.feed.postPrivate").unwrap();
        let did = Did::new("did:plc:exampleexampleexample").unwrap();
        let context = RecordEncryptionContext {
            nsid,
            originator: did.clone(),
            audience_list: None,
            trace_id: TraceId::from_bytes([0; 16]),
            operator_context: SmallVec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let resolver = AlwaysMalformedRecord;
        let err = resolver
            .encrypt_record(b"plaintext", &context, deadline)
            .await
            .unwrap_err();
        assert!(matches!(err, EncryptionError::Malformed));
    }
}

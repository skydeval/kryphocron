// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §8 at-rest hook surfaces.
//!
//! Two surfaces, on different tracks:
//!
//! - **§8.2 audit-event sensitive layers** — [`AuditEncryptionResolver`]
//!   plus the opaque [`AuditEncryptionKeyId`] and the empty
//!   [`AuditEncryptionAlgorithm`] enum. This surface is genuinely about
//!   *encryption* (confidentiality of forensic audit data) and ships as a
//!   surface-only door-open hook: v0.1 has no concrete resolver, and
//!   substrates configured without one emit audit events with
//!   [`crate::target::TargetRepresentation::sensitive`] = `None`. The
//!   [`produce_sensitive_representation`] helper is the §8.4 integration
//!   point.
//!
//! - **§8.3 record content at rest** — the [`ContentCodec`] trait and its
//!   surrounding vocabulary ([`EncodedRecord`], [`EncodeContext`],
//!   [`DecodeContext`], [`CodecId`], [`CodecError`], [`RotationOracle`],
//!   [`RotationGenerationMark`], …). Generalized from an encryption-specific
//!   hook to a *content-codec* seam: a `ContentCodec` impl may be encryption,
//!   friction (laquna-shaped), or anything with the round-trip shape — the
//!   trait asserts no confidentiality, authentication, or key-involvement.
//!   The substrate constructs the surrounding [`EncodedRecord`] (the codec
//!   has no authority over its metadata); rotation generation is sourced by
//!   the substrate from a [`RotationOracle`] via
//!   [`resolve_rotation_generation`]. 0.3 installs laquna by default via
//!   [`DefaultAtRestHooks`] — `content_codec()` is non-optional, so
//!   private-tier content is always encoded at rest (rev 3 §2.1).

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use smallvec::SmallVec;
use thiserror::Error;

use crate::audit::{BoundedString, BoundedStringTooLong};
use crate::authority::CapabilityKind;
use crate::identity::TraceId;
use crate::proto::{AtUri, Did, Nsid, RecordKey};
use crate::target::SensitiveRepresentation;

// ============================================================
// §8.2 — audit-event sensitive-layer encryption (unchanged).
// ============================================================

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

/// Algorithm tag for audit-encryption ciphertexts (§8.2).
///
/// **v1 ships no variants.** Future versions add variants like
/// `Aes256Gcm`, `ChaCha20Poly1305`; the enum is
/// `#[non_exhaustive]` from day one so additions are
/// backward-compatible.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditEncryptionAlgorithm {}

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

/// Failure cases for the §8.2 audit-encryption surface.
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
/// **v0.1 ships the trait surface only.** v1 has no default
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

/// Audit-emission integration helper (§8.4): produce a
/// [`SensitiveRepresentation`] from `plaintext` using the
/// installed audit resolver, OR return `None` when no resolver
/// is installed.
///
/// Substrate components emitting audit events with sensitive
/// data call this helper. The returned `Option` flows directly
/// into [`crate::target::TargetRepresentation::sensitive`].
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

// ============================================================
// §8.3 — record content at rest (ContentCodec seam).
// ============================================================

/// Inclusive maximum byte length of a [`CodecId`].
pub const MAX_CODEC_ID_LEN: usize = 128;
/// Inclusive maximum byte length of a [`RotationGenerationMark`].
pub const MAX_ROTATION_GENERATION_MARK_LEN: usize = 128;

/// Operator-namespaced codec identifier, URI-like (e.g. `"laquna/0.2"`).
///
/// No central registry — operators name their own codecs (§5.4); collisions
/// are operator responsibility. Persisted as `encodedContentCodec` on a
/// private-tier record; the read path uses it to verify the installed codec
/// matches the stored codec, failing closed with
/// [`CodecError::UnknownOrWrongCodec`] on mismatch. Wraps the crate's
/// [`BoundedString`] for the length bound and additionally constrains the
/// charset to ASCII alphanumerics plus `/ . - _`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodecId(BoundedString<MAX_CODEC_ID_LEN>);

/// Failure constructing a [`CodecId`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecIdError {
    /// Byte length exceeds [`MAX_CODEC_ID_LEN`].
    #[error("codec id too long: {len} bytes exceeds max {max}")]
    TooLong {
        /// Observed byte length.
        len: usize,
        /// Configured maximum ([`MAX_CODEC_ID_LEN`]).
        max: usize,
    },
    /// A disallowed character appears at the given byte index.
    #[error("codec id contains disallowed character at byte {index}")]
    InvalidCharset {
        /// Byte index of the first disallowed character.
        index: usize,
    },
    /// The identifier was empty.
    #[error("codec id is empty")]
    Empty,
}

impl CodecId {
    /// Construct a [`CodecId`], validating non-emptiness, the charset
    /// (ASCII alphanumeric plus `/ . - _`), and the [`MAX_CODEC_ID_LEN`]
    /// byte bound.
    ///
    /// # Errors
    ///
    /// [`CodecIdError`] on empty input, a disallowed character, or
    /// over-length input.
    pub fn new(s: impl Into<String>) -> Result<Self, CodecIdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(CodecIdError::Empty);
        }
        for (index, b) in s.bytes().enumerate() {
            if !(b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_')) {
                return Err(CodecIdError::InvalidCharset { index });
            }
        }
        let inner = BoundedString::new(s).map_err(|BoundedStringTooLong { len, bound }| {
            CodecIdError::TooLong { len, max: bound }
        })?;
        Ok(CodecId(inner))
    }

    /// Borrow the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for CodecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// Per-record marker recording which rotation *generation* a record was last
/// (re)written under — a per-record stamp, not an id of a shared batch.
///
/// Opaque and operator-namespaced: its format is coordinated host-side
/// between the operator's [`RotationOracle`] (which emits it) and their
/// [`ContentCodec`]; the substrate holds, persists, and indexes it opaquely
/// as `encodedContentGeneration`. **Ordering contract:** the host MUST pick a
/// lex-sortable encoding so that `<`-comparison on the persisted field yields
/// the temporal ordering of generation transitions (the substrate documents
/// but does not enforce this).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RotationGenerationMark(BoundedString<MAX_ROTATION_GENERATION_MARK_LEN>);

impl RotationGenerationMark {
    /// Construct a [`RotationGenerationMark`] from any string-convertible
    /// input, validating the [`MAX_ROTATION_GENERATION_MARK_LEN`] byte bound.
    ///
    /// # Errors
    ///
    /// [`BoundedStringTooLong`] when the input exceeds the byte bound.
    pub fn new(s: impl Into<String>) -> Result<Self, BoundedStringTooLong> {
        Ok(RotationGenerationMark(BoundedString::new(s)?))
    }

    /// Borrow the mark as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for RotationGenerationMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// §8.3 error type. Separate from §8.2's [`EncryptionError`]; carries a coarse
/// [`CodecErrorClass`] (via [`CodecError::class`]) that the audit pipeline
/// records without learning plaintext or the codec's full internal error.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecError {
    /// Stored content was structurally malformed for the codec.
    #[error("content malformed for codec {codec}")]
    Malformed {
        /// The codec that rejected the content.
        codec: CodecId,
    },
    /// The codec a record was stored under does not match the installed codec.
    #[error("unknown or wrong codec: stored {stored} != installed {installed}")]
    UnknownOrWrongCodec {
        /// Codec id read from the stored record.
        stored: CodecId,
        /// Codec id of the installed codec.
        installed: CodecId,
    },
    /// The rotation generation could not be resolved (no current generation,
    /// or the [`RotationOracle`] was stale / unreachable).
    #[error("rotation state unavailable for codec {codec}")]
    RotationStateUnavailable {
        /// The codec the encode was for.
        codec: CodecId,
    },
    /// Operation exceeded the supplied deadline. The `elapsed` value is for
    /// in-process classification only; hosts relying on §4.6
    /// timing-equalization properties MUST NOT log it to external
    /// observability channels (the audit boundary records only the class).
    #[error("codec deadline exceeded after {elapsed:?}")]
    DeadlineExceeded {
        /// How long the operation ran before the deadline check fired.
        elapsed: Duration,
    },
    /// The codec's backend was unavailable.
    #[error("codec backend unavailable: {detail}")]
    BackendUnavailable {
        /// Operator-facing detail string.
        detail: String,
    },
}

/// Coarse, plaintext-free classification of a [`CodecError`] for the audit
/// pipeline. The codec's own typed error stays codec-internal.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecErrorClass {
    /// See [`CodecError::Malformed`].
    Malformed,
    /// See [`CodecError::UnknownOrWrongCodec`].
    UnknownOrWrongCodec,
    /// See [`CodecError::RotationStateUnavailable`].
    RotationStateUnavailable,
    /// See [`CodecError::DeadlineExceeded`].
    DeadlineExceeded,
    /// See [`CodecError::BackendUnavailable`].
    BackendUnavailable,
}

impl CodecError {
    /// The coarse, plaintext-free [`CodecErrorClass`] for this error.
    #[must_use]
    pub fn class(&self) -> CodecErrorClass {
        match self {
            CodecError::Malformed { .. } => CodecErrorClass::Malformed,
            CodecError::UnknownOrWrongCodec { .. } => CodecErrorClass::UnknownOrWrongCodec,
            CodecError::RotationStateUnavailable { .. } => {
                CodecErrorClass::RotationStateUnavailable
            }
            CodecError::DeadlineExceeded { .. } => CodecErrorClass::DeadlineExceeded,
            CodecError::BackendUnavailable { .. } => CodecErrorClass::BackendUnavailable,
        }
    }
}

/// Context handed to [`ContentCodec::encode`].
///
/// Carries the record's full at-URI coordinates plus the substrate-resolved,
/// freshness-checked current-generation hint. A codec may *read* the hint to
/// stamp its output but has no authority over the resulting
/// [`EncodedRecord`]'s metadata (the substrate stamps it).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct EncodeContext {
    /// NSID of the record (the at-URI `collection`).
    pub nsid: Nsid,
    /// The at-URI `rkey` component of the record.
    pub rkey: RecordKey,
    /// DID of the record's originator (the at-URI authority).
    pub originator: Did,
    /// Audience-list reference, where applicable.
    pub audience_list: Option<AtUri>,
    /// Current rotation generation for this encode, sourced by the substrate
    /// from the installed [`RotationOracle`] and already freshness-checked.
    /// `None` when no rotation oracle is installed. Ignored by codecs with no
    /// rotation concept.
    pub current_generation_hint: Option<RotationGenerationMark>,
    /// Trace id correlating to the originating request.
    pub trace_id: TraceId,
    /// Operator-extensible context; the substrate does not interpret these.
    pub operator_context: SmallVec<[(String, Vec<u8>); 2]>,
}

/// Context handed to [`ContentCodec::decode`].
///
/// Unlike [`EncodeContext`], it carries no generation hint: the generation a
/// stored record was written under lives in [`EncodedRecord::generation`],
/// read from storage.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DecodeContext {
    /// NSID of the record (the at-URI `collection`).
    pub nsid: Nsid,
    /// The at-URI `rkey` component of the record.
    pub rkey: RecordKey,
    /// DID of the record's originator (the at-URI authority).
    pub originator: Did,
    /// Audience-list reference, where applicable.
    pub audience_list: Option<AtUri>,
    /// Trace id correlating to the originating request.
    pub trace_id: TraceId,
    /// Operator-extensible context; the substrate does not interpret these.
    pub operator_context: SmallVec<[(String, Vec<u8>); 2]>,
}

/// Codec-encoded record content as persisted, **constructed by the substrate**
/// at the encode seam.
///
/// The codec returns opaque bytes ([`ContentCodec::encode`]); the substrate
/// wraps them with its authoritative knowledge of the installed codec id and
/// the freshness-checked current generation. The codec has no authority over
/// the `codec` / `generation` metadata.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedRecord {
    /// The installed codec's id, stamped by the substrate (persisted as
    /// `encodedContentCodec`).
    pub codec: CodecId,
    /// The codec's opaque output bytes (persisted as `encodedContent`). The
    /// substrate does not interpret these.
    pub content: Vec<u8>,
    /// The freshness-checked current generation, stamped by the substrate from
    /// the resolved hint (persisted as `encodedContentGeneration`). `None` for
    /// rotation-less deployments.
    pub generation: Option<RotationGenerationMark>,
}

/// Transforms private-tier record content at rest. The substrate commits this
/// surface; a host fills it with a mechanism. The trait asserts **no** property
/// beyond encode/decode round-trip intent — not confidentiality, not
/// authentication, not key-involvement. An implementation MAY be encryption,
/// friction (laquna-shaped: a public, non-secret transform), or anything with
/// this shape.
///
/// Authorization is not this trait's concern: the §4.3 capability pipeline
/// (consulting the §4.5 [`crate::oracle::AudienceOracle`]) has already decided
/// the reader is authorized before `decode` fires. Rotation is sourced
/// externally: the substrate consults the installed [`RotationOracle`] and
/// passes the result as [`EncodeContext::current_generation_hint`].
///
/// v0.1 installs no codec; with none installed, record content is stored as
/// plaintext.
#[async_trait]
pub trait ContentCodec: Send + Sync {
    /// Stable, operator-namespaced identifier (e.g. `"laquna/0.2"`). The
    /// substrate may invoke this at install time and on each encode/decode
    /// seam call; an impl returning differing values across calls is outside
    /// the trait contract.
    fn codec_id(&self) -> CodecId;

    /// Encode record-content plaintext for storage, returning the codec's
    /// opaque output bytes. The substrate constructs the surrounding
    /// [`EncodedRecord`] from its own state — the codec has no authority over
    /// that metadata. MUST NOT be assumed to provide confidentiality.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on any codec-side failure.
    async fn encode(
        &self,
        plaintext: &[u8],
        context: &EncodeContext,
        deadline: Instant,
    ) -> Result<Vec<u8>, CodecError>;

    /// Decode stored content at read time (the reader is already authorized
    /// upstream). Returns plaintext, or a [`CodecError`] whose
    /// [`class`](CodecError::class) the audit pipeline records without learning
    /// plaintext.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on any codec-side failure.
    async fn decode(
        &self,
        encoded: &EncodedRecord,
        context: &DecodeContext,
        deadline: Instant,
    ) -> Result<Vec<u8>, CodecError>;

    /// Whether this codec semantically requires a [`RotationOracle`] to operate
    /// correctly. Default `false` (most codecs degrade cleanly to
    /// rotation-less). A codec returning `true` signals that installing it
    /// without a rotation oracle is a misconfiguration; the install seam
    /// (host-side) fails closed when `requires_rotation() && rotation_oracle().is_none()`.
    fn requires_rotation(&self) -> bool {
        false
    }
}

/// Context for [`RotationOracle::current_generation`]. Carries the account
/// identity (and audience reference) so the oracle can apply per-account and
/// per-audience rotation policy. Cadence is operator policy the oracle reads
/// from its own config; the substrate commits no cadence.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RotationContext {
    /// DID of the record's originator (the account).
    pub originator: Did,
    /// NSID of the record.
    pub nsid: Nsid,
    /// Audience-list reference, where applicable. Lets an oracle key rotation
    /// cadence on audience identity; oracles that don't care ignore it.
    pub audience_list: Option<AtUri>,
}

/// The deployment-wide source of the current rotation generation. A §4.5-family
/// oracle by trait shape (sync surface, freshness discipline) — though consulted
/// at the encode seam rather than the bind path. The substrate (not the
/// per-process codec) owns generation consistency; the oracle implementation
/// reads shared deployment state to answer consistently across processes.
///
/// Unlike the bind-path oracles, the rotation oracle does not participate in
/// §4.6 timing equalization (encode is out of the timing-channel threat model),
/// hence no `worst_case_latency_for` method.
pub trait RotationOracle: Send + Sync {
    /// Current deployment-wide generation for the given context, or `None` if
    /// the deployment has no rotation concept.
    fn current_generation(&self, ctx: &RotationContext) -> Option<RotationGenerationMark>;

    /// Wall-clock instant the oracle's data was last refreshed from
    /// authoritative storage. Used for freshness enforcement. Crosses process
    /// boundaries; production deployments SHOULD verify wall-clock parity (NTP
    /// or equivalent) between the oracle's reporting process and the
    /// substrate's calling processes.
    fn last_synced_at(&self) -> SystemTime;

    /// Maximum age of [`last_synced_at`](RotationOracle::last_synced_at) the
    /// oracle considers fresh. Past this, [`resolve_rotation_generation`] fails
    /// closed.
    fn data_freshness_bound(&self) -> Duration;
}

/// Explicit "no rotation" convenience [`RotationOracle`]: returns `None` and
/// never reads stale (its freshness bound is [`Duration::MAX`]). Installing it
/// is equivalent to `rotation_oracle() == None`; provided for symmetry.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRotationOracle;

impl RotationOracle for NoRotationOracle {
    fn current_generation(&self, _ctx: &RotationContext) -> Option<RotationGenerationMark> {
        None
    }
    fn last_synced_at(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
    fn data_freshness_bound(&self) -> Duration {
        Duration::MAX
    }
}

/// At-rest hook set installed at substrate startup. Bundles the at-rest
/// concerns: audit-event sensitive-layer encryption (§8.2), record-content
/// codec (§8.3), and the rotation oracle that feeds the codec.
pub trait AtRestHooks: Send + Sync {
    /// Audit-encryption resolver, if installed.
    fn audit(&self) -> Option<Arc<dyn AuditEncryptionResolver>>;
    /// Record-content codec. **Non-optional** — the substrate's typed write
    /// path always encodes private-tier record content at rest (rev 3 §2.1,
    /// the structural encoding-at-default floor). There is no opt-out: a
    /// deployment that does not encode private-tier records at rest is not a
    /// kryphocron deployment. Operators substitute toward *strengthening*
    /// codecs (authenticated encryption, HSM-backed, …) via
    /// [`DefaultAtRestHooksBuilder::with_codec`]; substitution toward weaker
    /// or identity codecs configures something that is not kryphocron.
    fn content_codec(&self) -> Arc<dyn ContentCodec>;
    /// The rotation oracle serving `content_codec`. `None` ⇒ rotation-less
    /// deployment (encode hint is `None`).
    fn rotation_oracle(&self) -> Option<Arc<dyn RotationOracle>>;
}

/// The default [`AtRestHooks`] baseline shipped with kryphocron 0.3.0
/// (rev 3 §5). Installs laquna as the at-rest content codec and a
/// [`DefaultRotationOracle`](crate::codec::laquna::DefaultRotationOracle). No
/// audit-encryption resolver.
///
/// Recommended baseline for operators who do not need custom hooks. The
/// substrate's constitutional claim — that private-tier records are encoded at
/// rest via the substrate's typed write path — is delivered by this baseline
/// out of the box.
///
/// **Single-process deployments only** for the default rotation oracle (see
/// the oracle's §4.1 docs). Multi-process deployments substitute a coordinated
/// rotation oracle via [`DefaultAtRestHooksBuilder::with_rotation_oracle`]
/// regardless of user count.
///
/// Construction is **fallible** — the inner `DefaultRotationOracle`
/// construction performs CSRNG initialization and an install-time write check
/// at `<data_dir>/kryphocron/rotation.state`; both can fail at construction.
/// Operators handle the `Result` at the install seam; failures here are
/// catchable diagnostically.
///
/// Construction:
/// - [`DefaultAtRestHooks::for_data_dir`] — zero-config; laquna with the
///   default seed policy and a default rotation oracle persisting to
///   `<path>/kryphocron/rotation.state`.
/// - [`DefaultAtRestHooks::builder`] — for operators substituting the codec,
///   the audit resolver, or the rotation oracle. The `data_dir` provided at
///   `builder(path)` is the substrate's data root; if `with_rotation_oracle`
///   is not called, the builder defaults the rotation oracle to
///   `DefaultRotationOracle::for_data_dir(path)?`.
///
/// Operators implementing custom `AtRestHooks` (e.g. to install completely
/// custom oracle infrastructure) implement the trait directly rather than
/// using this struct.
#[derive(Clone)]
pub struct DefaultAtRestHooks {
    codec: Arc<dyn ContentCodec>,
    rotation_oracle: Arc<dyn RotationOracle>,
    audit: Option<Arc<dyn AuditEncryptionResolver>>,
}

impl DefaultAtRestHooks {
    /// Zero-config construction. Installs laquna with the default seed policy
    /// and `DefaultRotationOracle::for_data_dir(data_dir)?`.
    ///
    /// # Errors
    ///
    /// [`RotationOracleConstructionError`](crate::codec::laquna::RotationOracleConstructionError)
    /// if the inner rotation-oracle construction fails (CSRNG failure or
    /// install-time write check failure at the data dir).
    pub fn for_data_dir(
        data_dir: PathBuf,
    ) -> Result<Self, crate::codec::laquna::RotationOracleConstructionError> {
        Ok(Self {
            codec: Arc::new(crate::codec::laquna::Codec::default()),
            rotation_oracle: Arc::new(
                crate::codec::laquna::DefaultRotationOracle::for_data_dir(data_dir)?,
            ),
            audit: None,
        })
    }

    /// Builder construction. `data_dir` is the substrate's data root; it is
    /// used to default the rotation oracle to
    /// `DefaultRotationOracle::for_data_dir(data_dir)?` if `with_rotation_oracle`
    /// is not called. If the operator does call `with_rotation_oracle`, the
    /// `data_dir` is ignored for rotation-oracle purposes (the operator-supplied
    /// oracle is used). Operators not substituting the oracle get the same
    /// zero-config rotation oracle as `for_data_dir(path)`.
    #[must_use]
    pub fn builder(data_dir: PathBuf) -> DefaultAtRestHooksBuilder {
        DefaultAtRestHooksBuilder {
            data_dir,
            codec: None,
            rotation_oracle: None,
            audit: None,
        }
    }
}

/// Builder for [`DefaultAtRestHooks`] (rev 3.1 §2).
pub struct DefaultAtRestHooksBuilder {
    data_dir: PathBuf,
    codec: Option<Arc<dyn ContentCodec>>,
    rotation_oracle: Option<Arc<dyn RotationOracle>>,
    audit: Option<Arc<dyn AuditEncryptionResolver>>,
}

impl DefaultAtRestHooksBuilder {
    /// Substitute the content codec.
    ///
    /// **Substitution is a strengthening path** (rev 3 §1.2 #4, §1.3, §5.5).
    /// Install codecs delivering guarantees stronger than laquna's friction —
    /// authenticated encryption codecs, HSM-backed encryption codecs, codecs
    /// with hardware-attested key custody, etc. Substitution toward weaker
    /// guarantees — identity-function codecs, no-op encoders, codecs that emit
    /// plaintext under any record-shape — is **not a supported configuration**.
    /// An operator installing an identity-function codec is running a
    /// deployment that is not kryphocron, in the same sense that an operator
    /// forking the source and deleting the codec call is running a deployment
    /// that is not kryphocron. Kryphocron's identity is encoding-at-default;
    /// configurations that opt out of that identity are not kryphocron
    /// deployments. See the kryphocron README's privacy-posture section for the
    /// operator-facing framing.
    #[must_use]
    pub fn with_codec(mut self, codec: Arc<dyn ContentCodec>) -> Self {
        self.codec = Some(codec);
        self
    }

    /// Substitute the rotation oracle.
    ///
    /// Multi-process deployments install a coordinated `RotationOracle` here
    /// from day one (see the oracle's §4.1 docs). `DefaultRotationOracle` is a
    /// single-process starter oracle; multi-process deployments substitute it
    /// for a coordinated implementation (DB-backed, KMS-backed, etc.) at
    /// install time, not "as they scale."
    ///
    /// If this method is called, the `data_dir` passed to `builder(path)` is no
    /// longer used for rotation-oracle defaulting; the operator-supplied oracle
    /// is used directly.
    #[must_use]
    pub fn with_rotation_oracle(mut self, oracle: Arc<dyn RotationOracle>) -> Self {
        self.rotation_oracle = Some(oracle);
        self
    }

    /// Install an audit-encryption resolver (§8.2).
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AuditEncryptionResolver>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Build the `DefaultAtRestHooks`. Fallible because the default rotation
    /// oracle's construction is fallible; if the operator called
    /// `with_rotation_oracle`, no fallible construction happens here and
    /// `build()` cannot fail.
    ///
    /// # Errors
    ///
    /// [`RotationOracleConstructionError`](crate::codec::laquna::RotationOracleConstructionError)
    /// from the default rotation oracle's construction (only when
    /// `with_rotation_oracle` was not called).
    pub fn build(
        self,
    ) -> Result<DefaultAtRestHooks, crate::codec::laquna::RotationOracleConstructionError> {
        // rev 3.2 §6: explicit type annotations defend against inference
        // fragility on the unsized `Arc<Concrete> -> Arc<dyn _>` coercions.
        let codec: Arc<dyn ContentCodec> = self
            .codec
            .unwrap_or_else(|| Arc::new(crate::codec::laquna::Codec::default()));
        let rotation_oracle: Arc<dyn RotationOracle> = match self.rotation_oracle {
            Some(o) => o,
            None => Arc::new(crate::codec::laquna::DefaultRotationOracle::for_data_dir(
                self.data_dir,
            )?),
        };
        Ok(DefaultAtRestHooks {
            codec,
            rotation_oracle,
            audit: self.audit,
        })
    }
}

impl AtRestHooks for DefaultAtRestHooks {
    fn audit(&self) -> Option<Arc<dyn AuditEncryptionResolver>> {
        self.audit.clone()
    }
    fn content_codec(&self) -> Arc<dyn ContentCodec> {
        self.codec.clone()
    }
    fn rotation_oracle(&self) -> Option<Arc<dyn RotationOracle>> {
        Some(self.rotation_oracle.clone())
    }
}

/// §8.4-style helper (mirrors [`produce_sensitive_representation`]): resolve the
/// current rotation generation for an encode, enforcing oracle freshness in
/// substrate code so a host cannot accidentally skip the check.
///
/// Freshness is checked **before** the value is consulted: if the oracle is
/// stale (`now - last_synced_at() > data_freshness_bound()`) or future-dated,
/// returns [`CodecError::RotationStateUnavailable`] regardless of what
/// `current_generation` would return. Only after the freshness check passes is
/// `current_generation(ctx)` invoked; its `None` becomes the helper's
/// `Ok(None)`. A `None` oracle (none installed) ⇒ `Ok(None)` (rotation-less).
///
/// The substrate does not retry: a failure returns to the host, whose retry
/// layer (if any) reconstructs the encode call from scratch including a fresh
/// call here.
///
/// # Errors
///
/// [`CodecError::RotationStateUnavailable`] when the installed oracle is stale
/// or future-dated.
pub fn resolve_rotation_generation(
    oracle: Option<&dyn RotationOracle>,
    codec: &CodecId,
    ctx: &RotationContext,
    now: SystemTime,
) -> Result<Option<RotationGenerationMark>, CodecError> {
    match oracle {
        None => Ok(None),
        Some(o) => {
            let stale = match now.duration_since(o.last_synced_at()) {
                Ok(age) => age > o.data_freshness_bound(),
                // Future-dated last_synced_at (clock skew): fail closed.
                Err(_) => true,
            };
            if stale {
                return Err(CodecError::RotationStateUnavailable {
                    codec: codec.clone(),
                });
            }
            Ok(o.current_generation(ctx))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- §8.2 (unchanged) ----

    #[test]
    fn audit_algorithm_enum_has_zero_v1_variants() {
        // §8.5: "v1 ships no algorithm variants." Adding one would be a
        // commitment-breaking change.
        fn _assert_audit_alg_zero_variants(a: AuditEncryptionAlgorithm) -> ! {
            match a {}
        }
    }

    #[test]
    fn audit_key_id_bytes_round_trip() {
        let bytes = [0xCC; 32];
        assert_eq!(AuditEncryptionKeyId::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[tokio::test]
    async fn produce_sensitive_returns_none_when_resolver_absent() {
        let context = EncryptionContext {
            capability: CapabilityKind::ViewPrivate,
            trace_id: TraceId::from_bytes([0; 16]),
            operator_context: SmallVec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let result = produce_sensitive_representation(b"plaintext", &context, deadline, None)
            .await
            .unwrap();
        assert!(result.is_none());
    }

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

    // ---- §8.3 ContentCodec surface ----

    #[test]
    fn codec_id_new_validates() {
        assert_eq!(CodecId::new("laquna/0.2").unwrap().as_str(), "laquna/0.2");
        assert!(matches!(CodecId::new(""), Err(CodecIdError::Empty)));
        assert!(matches!(
            CodecId::new("bad space"),
            Err(CodecIdError::InvalidCharset { index: 3 })
        ));
        let over = "a".repeat(MAX_CODEC_ID_LEN + 1);
        assert!(matches!(
            CodecId::new(over),
            Err(CodecIdError::TooLong {
                len,
                max: MAX_CODEC_ID_LEN
            }) if len == MAX_CODEC_ID_LEN + 1
        ));
    }

    #[test]
    fn rotation_generation_mark_round_trips_and_bounds() {
        assert_eq!(RotationGenerationMark::new("000042").unwrap().as_str(), "000042");
        let over = "a".repeat(MAX_ROTATION_GENERATION_MARK_LEN + 1);
        assert!(RotationGenerationMark::new(over).is_err());
    }

    #[test]
    fn codec_error_class_maps_each_variant() {
        let c = CodecId::new("laquna/0.2").unwrap();
        assert_eq!(
            CodecError::Malformed { codec: c.clone() }.class(),
            CodecErrorClass::Malformed
        );
        assert_eq!(
            CodecError::RotationStateUnavailable { codec: c }.class(),
            CodecErrorClass::RotationStateUnavailable
        );
        assert_eq!(
            CodecError::DeadlineExceeded {
                elapsed: Duration::from_secs(1)
            }
            .class(),
            CodecErrorClass::DeadlineExceeded
        );
    }

    #[test]
    fn default_at_rest_hooks_installs_real_codec_and_oracle() {
        // The encoding-at-default floor (rev 3 §2.1): the baseline always
        // installs a real codec (content_codec is non-optional) and a rotation
        // oracle. No audit-encryption resolver by default.
        let dir = std::env::temp_dir().join(format!(
            "kryphocron-hooks-{}-{}",
            std::process::id(),
            "default"
        ));
        let hooks = DefaultAtRestHooks::for_data_dir(dir.clone()).expect("construct");
        assert_eq!(hooks.content_codec().codec_id().as_str(), "laquna/0.2");
        assert!(hooks.rotation_oracle().is_some());
        assert!(hooks.audit().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct StubOracle {
        generation: Option<RotationGenerationMark>,
        synced: SystemTime,
        bound: Duration,
    }

    impl RotationOracle for StubOracle {
        fn current_generation(&self, _ctx: &RotationContext) -> Option<RotationGenerationMark> {
            self.generation.clone()
        }
        fn last_synced_at(&self) -> SystemTime {
            self.synced
        }
        fn data_freshness_bound(&self) -> Duration {
            self.bound
        }
    }

    fn rotation_ctx() -> RotationContext {
        RotationContext {
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            audience_list: None,
        }
    }

    #[test]
    fn resolve_rotation_generation_no_oracle_is_none() {
        let codec = CodecId::new("laquna/0.2").unwrap();
        let got = resolve_rotation_generation(None, &codec, &rotation_ctx(), SystemTime::now())
            .unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn resolve_rotation_generation_fresh_returns_value() {
        let codec = CodecId::new("laquna/0.2").unwrap();
        let now = SystemTime::now();
        let oracle = StubOracle {
            generation: Some(RotationGenerationMark::new("000042").unwrap()),
            synced: now,
            bound: Duration::from_secs(3600),
        };
        let got = resolve_rotation_generation(Some(&oracle), &codec, &rotation_ctx(), now)
            .unwrap()
            .unwrap();
        assert_eq!(got.as_str(), "000042");
    }

    #[test]
    fn resolve_rotation_generation_stale_fails_closed() {
        let codec = CodecId::new("laquna/0.2").unwrap();
        let now = SystemTime::now();
        let oracle = StubOracle {
            generation: Some(RotationGenerationMark::new("000042").unwrap()),
            synced: now - Duration::from_secs(7200),
            bound: Duration::from_secs(3600),
        };
        let err = resolve_rotation_generation(Some(&oracle), &codec, &rotation_ctx(), now)
            .unwrap_err();
        assert_eq!(err.class(), CodecErrorClass::RotationStateUnavailable);
    }

    #[test]
    fn no_rotation_oracle_never_stale_and_none() {
        let codec = CodecId::new("laquna/0.2").unwrap();
        let oracle = NoRotationOracle;
        let got = resolve_rotation_generation(Some(&oracle), &codec, &rotation_ctx(), SystemTime::now())
            .unwrap();
        assert!(got.is_none());
    }
}

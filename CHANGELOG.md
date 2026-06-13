# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0] — 2026-06-13

### Added

- `encryption::ContentCodec` — the at-rest content-transform trait (`codec_id`,
  `encode -> Vec<u8>`, `decode`, `requires_rotation`). May host encryption,
  friction-encoding, or any round-trip transform; the trait asserts no
  confidentiality, authentication, or key property of its own.
- `encryption::{EncodedRecord, EncodeContext, DecodeContext, CodecId,
  CodecIdError, CodecError, CodecErrorClass, RotationOracle, RotationContext,
  RotationGenerationMark, NoRotationOracle, AtRestHooks,
  resolve_rotation_generation}`.
- `at_rest::{encode_record_content, decode_record_content,
  RecordContentContext}` — the substrate-side encode/decode seams that drive the
  codec, stamp `EncodedRecord` metadata from substrate state, and emit the
  content-encode/decode audit events.
- `at_rest::{validate_at_rest_install, AtRestInstallError}` — install-time
  fail-closed check for a codec that requires a rotation oracle.
  `AtRestInstallError::OracleYieldsNoGeneration { codec }` +
  `RotationContext::for_install_probe()`: install now probes the oracle's *yield*
  (not just its presence) when the codec sets `requires_rotation()`, so a
  rotation-requiring codec paired with an oracle that yields no generation (e.g.
  `NoRotationOracle`) fails closed at install instead of at first encode. (An
  oracle healthy at install that later yields nothing returns the existing
  `CodecError::RotationStateUnavailable` at encode, not a panic.)
- `read_pipeline::{ReadAuthorization, ReadPipelineStage, RecordValidation,
  validate_record, validate_record_for_write, validate_record_for_read}` —
  structural validation (`text`/`encodedContent` XOR, orphan-metadata rules, the
  `policy.audience` `members` rule under `mode == "list"`) plus a sealed
  post-authorization witness that makes read-path validation and decode a
  compile-time-enforced post-auth property.
- Audit events: `UserAuditEvent::{ContentEncoded, ContentEncodeFailed,
  ContentDecodeFailed}`, `SubstrateAuditEvent::{MalformedRecordRejected,
  RewriteOnRotateStarted, RewriteOnRotateProgress, RewriteOnRotateTerminated}`,
  the `RewriteOnRotateOutcome` and `MalformedRecordReason` enums, and
  `OracleKind::Rotation`. `EVENT_SCHEMA_VERSION` 1.0.0 → 1.1.0 (additive).
- `kryphocron::codec::laquna` module — the built-in default `ContentCodec`,
  friction-encoding for at-rest content (vendored from laquna v0.2). Pulls in
  `chacha20`, `hkdf`, `sha2`, `ruzstd`, `zstd`, `hex` as direct dependencies;
  `zstd` binds to C libzstd via `zstd-sys` (the one non-Rust build dependency).
- `kryphocron::codec::laquna::DefaultRotationOracle` — default `RotationOracle`
  for **single-process** deployments: 24-hour cadence, CSRNG slug generation,
  lex-sortable mark format. Construction is fallible, with an install-time write
  check at `<data_dir>/kryphocron/rotation.state`; builder-configurable.
- `kryphocron::codec::laquna::RotationOracleConstructionError` — construction
  error for `DefaultRotationOracle` (CSRNG failure, initial-write failure).
- `encryption::DefaultAtRestHooks` + `DefaultAtRestHooksBuilder` — the baseline
  hooks, installing laquna + `DefaultRotationOracle`. Construct via
  `DefaultAtRestHooks::for_data_dir(path)?` or `builder(path).build()?` (the
  builder's `with_rotation_oracle` substitutes the oracle).
  `with_codec` substitution is restricted to **strengthening** codecs
  (authenticated/HSM-backed encryption); identity and weakening codecs are
  unsupported (encoding-at-default is the floor).
- `build.rs` generating per-record `HasNsid` impls (each with a `sealed::Sealed`
  impl) and the `KRYPHOCRON_IMPLEMENTED_NSIDS` constant from
  `KRYPHOCRON_LEXICON_REGISTRY`, with a compile-time consistency assertion.
  Without it the sealed `HasNsid` trait had zero implementors and `Tiered<_, _>`
  was uninhabitable for consumers. `tests/has_nsid_impls.rs` covers it.
- Public `ServiceIdentity::new(service_did, key_id, key_material,
  rotation_evidence)` — consumers can construct their own service's audience
  identity for `verify_jwt`'s `local_audience` (previously only reachable via the
  `test-support`-gated `new_for_test`).
- Public `new(...)` constructors on `DidDocument` and `DidService` — unblocks
  operator-implemented `DidResolver`s and test fixtures. `#[non_exhaustive]` is
  preserved.
- `tests/public_constructors.rs` — external-crate-boundary tests proving the new
  constructors are reachable by consumers.

### Changed

- `bind()` now consults the `AudienceOracle` for every capability declaring an
  `AudienceOracleQuery` (`ViewPrivate`, `ParticipatePrivate`, `EditPrivatePost`).
  A non-`InAudience` result denies the bind inline at
  `PipelineStage::AudienceConsultation` (`DenialReason::NotInAudience`, covering
  both `NotInAudience` and `NoAudienceConfigured`); a stale or future-dated
  oracle fails closed via `OracleStale`. The per-capability `OracleResults`
  audience field is now `Option<AudienceState>` and the predicate backstop fails
  closed on `None`, so an unconsulted audience cannot read as a grant.
  Previously these binds did not consult the oracle. No new audit-event,
  `DenialReason`, or `PipelineStage` variants were required.
- `kryphocron-lexicons` dependency `0.2` → `0.3`: consumes the `postPrivate`
  codec fields plus the lexicon-evolution changes (optional `publicCompanion` on
  `postPrivate`; optional `mode`/`members`/`name` on `policy.audience`;
  `postPrivate.audienceList` corrected from a record-def ref to an at-uri
  string). `KRYPHOCRON_CODEGEN_HASH` shifts accordingly.

### Changed (breaking)

No deprecation aliases — rename your `impl` sites and references:

- **Encryption surface renamed to a content-codec surface:**
  - `RecordEncryptionResolver` → `ContentCodec`
  - `EncryptedRecord` → `EncodedRecord`
  - `RecordEncryptionContext` → split into `EncodeContext` + `DecodeContext`
  - `EncryptionResolverSet` → `AtRestHooks`
- **`ContentCodec::encode` returns `Vec<u8>`** (was returning the full record);
  the substrate now constructs `EncodedRecord` and stamps its metadata.
- **`ContentCodec::decode` no longer takes a `reader` parameter.**
- **`AtRestHooks::content_codec()` returns `Arc<dyn ContentCodec>`** (was
  `Option<Arc<dyn ContentCodec>>`). The no-codec path is gone from the public
  API; records written via the at-rest path are never plaintext.
- **`at_rest::encode_record_content` returns `Result<EncodedRecord, CodecError>`**
  (was `Result<Option<EncodedRecord>, CodecError>`); the encode seam always
  produces an encoded record.

### Removed

- `NoEncryption` — the no-op resolver set. The at-rest write path is now always
  encoding (encoding-at-default). Migrate to
  `DefaultAtRestHooks::for_data_dir(path)?`.
- `RecordEncryptionKeyId`, `RecordEncryptionAlgorithm`, and the prior
  `EncryptedRecord` / `RecordEncryptionContext` / `RecordEncryptionResolver` /
  `EncryptionResolverSet` (replaced per the renames above).
- `CodecError::NoCodecInstalled` + `CodecErrorClass::NoCodecInstalled` — a
  decode-error variant introduced and removed within this cycle; cross-codec
  deployment skew is handled by the existing `CodecError::UnknownOrWrongCodec`.

### Fixed

- `AuthContext<'a>` is now `Send + Sync`. A `PhantomData<*const ()>` marker meant
  to forbid `Clone` had, as a side effect, propagated `!Send + !Sync`, making
  `AuthContext` (and `&AuthContext`) unusable across an `.await` on `Send`-future
  executors (multi-thread tokio / axum) — which also made the substrate's own
  async `bind` path unusable from such handlers. The marker is removed; the type
  remains `!Clone` (it has no `Clone` impl), and compile-time `Send + Sync`
  assertions guard against regressions.

### Documentation

- `ContentCodec` trait rustdoc de-staled (laquna is the default codec);
  `DefaultAtRestHooksBuilder::with_codec` carries the strengthening-only floor.
- Documented that `at_rest::{encode_record_content, decode_record_content}` audit
  emits are **fire-and-forget** (an unavailable sink does not fail the
  encode/decode), distinct from the fail-closed capability-bind path; the
  `MalformedRecordReason` codec-orphan vs generation-orphan asymmetry; and that
  the `policy.audience` `members` rule binds only under `mode == "list"`.

### Known limitations

- `audit-serde-json` derive wiring is partial. The feature flag is structurally
  wired and the `serde` / `serde_json` dependencies are correctly optional —
  both `cargo build --features audit-serde-json` and `cargo build` succeed — but
  not every reachable type yet carries the `Serialize`/`Deserialize` derives.
  Closing it requires derive additions across `crate::identity`
  (`ServiceIdentity`'s sealed-token `PhantomData`; `Instant` fields in
  `BindOutcomeRepr::Expired`), `kryphocron-lexicons` (`SemVer`, `Nsid`, `Did`),
  and downstream crates. Operators planning to consume the JSON audit stream
  should know the derive coverage is incomplete this cycle.

## [0.2.0] — 2026-06-02

### Added

- `lexicons()` accessor (re-exported from `kryphocron-lexicons`) returning the
  lexicon document collection for runtime validation, suitable for use with
  `proto_blue_lexicon::validate_record`.

## [0.1.0] — 2026-05-17

Initial publication release — the kryphocron substrate's authority discipline,
end to end.

### Added

- Capability issuance chokepoints `issue_user`, `issue_channel`,
  `issue_substrate`, `issue_moderation`, with per-class requester-authority
  enforcement (substrate / moderation are Service-only).
- Bind + reborrow pipeline across all four capability classes (`UserProof`,
  `ChannelProof`, `SubstrateProof`, `ModerationProof`): pre-checks → deprecation
  gate → oracle consultation (user-class) → predicate → audit emit → timing
  equalization → return.
- `AuthContext::derive_for` with three legal narrowings (`ToAnonymous`,
  `NarrowCapabilities`, `ServiceToService`), emitting `DerivedContext` audit
  events on every attempt via fire-and-forget user-sink dispatch.
- `tier::visible_to(tier, ctx)` — the tier × requester-class visibility
  predicate.
- `equalize_timing` + `equalize_timing_target_for::<C>` (tokio-backed
  sleep-to-target).
- `composite_audit` machinery: class-priority commit order (substrate →
  moderation → user → channel), rollback fan-out to already-committed sinks, and
  fallback-sink escalation with `catch_unwind` panic catchment.
- `InspectionNotificationQueueImpl` trait + the `NoInspectionNotifications` no-op
  default for moderation-class inspection-notification fan-out (outside
  composite-rollback semantics).
- `ingress::AuditSinks` fields `inspection_queue` and `correlation_key`.
- `HasResourceLocation` sealed trait surface for deprecation-gate NSID extraction
  (on `ResourceId`, `ManageAudienceSubject`, `ModerationSubject`).
- `RequesterKind` discriminator + `Requester::kind()` accessor.
- `AuthDenial::RequesterLacksAuthority { class, found }`,
  `DenialReason::CapabilityDeprecated { nsid, since_version, successor }`, and
  `BindError::DeniedAtPipeline { stage, reason }` variants;
  `From<CompositeAuditError> for BindError`.
- `ingress::anonymous_for_public_read(trace_id, sinks, oracles)` constructor.
- Publication-quality README + crate-root rustdoc.

### Changed

- All `*Proof::bind` and `Bound*Proof::reborrow` methods are now `async fn` (the
  bind pipeline runs inside `composite_audit`, which is async).
- `derive_for<N: Narrowing>` gained a `+ 'static` bound (internal `Any`-based
  narrowing dispatch).
- `ingress::anonymous_for_public_read` gained a `trace_id` parameter.
- `ModerationProof::bind` takes a fourth `rationale: ModeratorRationale`
  argument; the other three classes' bind methods take `(self, ctx, target)`
  only. Generic bind-dispatch code must handle this asymmetry — rationale is
  bind-time, not issuance-time, input.
- License set to MPL-2.0 (crate code), with per-file headers; the companion
  `kryphocron-lexicons` crate ships under `MPL-2.0 AND CC0-1.0`.
- `tokio` promoted from a dev-only to a production dependency (the `time`
  feature, for timing-channel equalization). Operators on a non-tokio runtime
  supply a tokio-compatible reactor or shim.
- Cargo.toml metadata polished for crates.io; `publish = false` removed.

### Removed

- `from_sync_channel_handshake` constructor and the `VerifiedHandshake` type —
  unwired pre-1.0 surfaces, superseded by the three-message sync-handshake
  protocol (`VerifiedSyncHello`, `VerifiedSyncAccept`, `VerifiedSyncEstablished`)
  + `VerifiedSyncMessage`.
- `construct_user_proof` — subsumed by `issue_user`.

### Known limitations

- Several audit-event payload fields ship with placeholder data pending sealed
  per-class extraction traits (channel-class peer + session id, substrate-class
  scope kind, moderation-class case id). The `composite_audit` emission is
  exercised end-to-end; forensic detail is degraded for non-user classes.

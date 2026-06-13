# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0] — UNRELEASED

The 0.3 cycle generalizes §8.3's record-content hook from encryption-specific
to a content-codec seam (the `ContentCodec` at-rest content-transform surface)
and wires the encode / decode / validation plumbing the substrate had only
committed as forward surface. The §8.3 API changes are **breaking** (clean
rename, no deprecation aliases). §8.2 (`AuditEncryptionResolver`) is unchanged.
The build-system / constructor work below (previously drafted under 0.2.1-dev)
ships as part of 0.3.0.

### §8.3 content-codec generalization — Added

- `encryption::ContentCodec` — the at-rest content-transform trait (`codec_id`,
  `encode -> Vec<u8>`, `decode`, `requires_rotation`). May host encryption,
  friction (laquna-shaped), or any round-trip transform; the trait asserts no
  confidentiality / authentication / key property.
- `encryption::{EncodedRecord, EncodeContext, DecodeContext, CodecId,
  CodecIdError, CodecError, CodecErrorClass, RotationOracle, RotationContext,
  RotationGenerationMark, NoRotationOracle, AtRestHooks, NoAtRestHooks,
  resolve_rotation_generation}`.
- `at_rest::{encode_record_content, decode_record_content,
  RecordContentContext}` — the substrate-side encode/decode seams that drive
  the codec, stamp the `EncodedRecord` metadata from substrate state, and emit
  the §6.2/§6.3 audit events.
- `at_rest::{validate_at_rest_install, AtRestInstallError}` — install-time
  fail-closed check for a codec that requires a rotation oracle.
- `read_pipeline::{ReadAuthorization, ReadPipelineStage, RecordValidation,
  validate_record, validate_record_for_write, validate_record_for_read}` — the
  §5.4 / §4.2 structural validation (`text`/`encodedContent` XOR + the
  orphan-metadata rules + the `policy.audience` `mode == "list"` members rule)
  and the sealed post-authorization witness that makes read-path validation and
  decode a **compile-time-enforced post-auth** property.
- Audit (§6): `UserAuditEvent::{ContentEncoded, ContentEncodeFailed,
  ContentDecodeFailed}`, `SubstrateAuditEvent::{MalformedRecordRejected,
  RewriteOnRotateProgress, RewriteOnRotateStarted, RewriteOnRotateTerminated}`,
  the `RewriteOnRotateOutcome` and `MalformedRecordReason` enums, and
  `OracleKind::Rotation`. `EVENT_SCHEMA_VERSION` 1.0.0 → 1.1.0 (additive
  variants; schema-minor per §6.9).
- `CodecError::NoCodecInstalled` + `CodecErrorClass::NoCodecInstalled` — an
  **implementation-cycle gap-fill, not in the rev-6 design**: the locked design's
  enumerated decode errors did not cover "no codec installed but the record
  carries codec-encoded content" (cross-peer codec skew, or reading historical
  records written before any codec was installed). `ContentDecodeFailed.codec`
  is `Option<CodecId>` accordingly (`None` ⇒ no codec installed; `stored_codec`
  carries the codec the record needed).

### §8.3 content-codec generalization — Changed (breaking)

- Renamed `RecordEncryptionResolver` → `ContentCodec`, `EncryptedRecord` →
  `EncodedRecord`, `RecordEncryptionContext` → split `EncodeContext` +
  `DecodeContext`, `EncryptionResolverSet` → `AtRestHooks`, `NoEncryption` →
  `NoAtRestHooks`. `ContentCodec::encode` returns `Vec<u8>` (the substrate now
  constructs `EncodedRecord` and stamps its metadata); `decode` no longer takes
  a `reader`. **No deprecation aliases** — consumers rename their `impl` sites
  and references.
- `kryphocron-lexicons` dependency `0.2` → `0.3` (consumes the `postPrivate`
  codec fields).

### §8.3 content-codec generalization — Removed

- `RecordEncryptionKeyId`, `RecordEncryptionAlgorithm`, the rev-1
  `EncryptedRecord` / `RecordEncryptionContext`, `RecordEncryptionResolver`,
  `EncryptionResolverSet`, `NoEncryption` (all replaced per the rename above).

### default-codec arc (laquna built-in) — Added

- `kryphocron::codec::laquna` module — the default `ContentCodec`
  implementation: friction-encoding for at-rest content, vendored from
  laquna v0.2 as the substrate's built-in default. Vendoring pulls in
  laquna's dependency tree as direct dependencies (`chacha20`, `hkdf`,
  `sha2`, `ruzstd`, `zstd`, `hex`; `blake3` / `getrandom` already present).
  **`zstd` is a binding to C libzstd** (`zstd-sys`) — the one non-Rust build
  dependency the default codec introduces.
- `kryphocron::codec::laquna::DefaultRotationOracle` — the default
  `RotationOracle` shipped alongside laquna for **single-process**
  deployments. 24-hour wall-clock cadence, CSRNG slug generation,
  lex-sortable mark format (`"laquna/{unix_secs:020}/{hex_slug}"`).
  Construction is fallible; install-time write check at
  `<data_dir>/kryphocron/rotation.state`. Configurable via builder.
- `kryphocron::codec::laquna::RotationOracleConstructionError` —
  construction-time error type for `DefaultRotationOracle` (CSRNG failure
  and initial-persistence-write failure).
- `encryption::DefaultAtRestHooks` + `DefaultAtRestHooksBuilder` — the new
  baseline; installs laquna + `DefaultRotationOracle`. Constructed via
  `for_data_dir(path)?` or `builder(path).build()?`. The builder takes the
  `data_dir` at construction; operators not substituting `with_rotation_oracle`
  get the same default rotation oracle as `for_data_dir(path)`. Substitution
  via `with_codec` is restricted to **strengthening** configurations
  (authenticated encryption, HSM-backed encryption, etc.); identity codecs and
  weakening substitutions are not supported configurations per kryphocron's
  identity (encoding-at-default).
- README: privacy-posture section absorbing laquna's threat-model framing,
  the principle-stance note on the codec/rotation surfaces, and the
  deployment-shape constraint for `DefaultRotationOracle` (single-process;
  multi-process deployments install a coordinated `RotationOracle` from day
  one).

- `AtRestInstallError::OracleYieldsNoGeneration { codec }` +
  `RotationContext::for_install_probe()` — `validate_at_rest_install` now probes
  the installed rotation oracle (not just its presence) when the codec declares
  `requires_rotation()`, so a rotation-requiring codec paired with an oracle
  that yields no generation (e.g. `NoRotationOracle`) fails closed at install
  rather than at first encode. The adapter's encode returns the existing
  `CodecError::RotationStateUnavailable` (not a panic) if a healthy-at-install
  oracle later returns no generation (runtime transient).

### default-codec arc (laquna built-in) — Changed (breaking)

- `AtRestHooks::content_codec()` returns `Arc<dyn ContentCodec>` (was
  `Option<Arc<dyn ContentCodec>>`). The no-codec path is removed from the
  public API; records produced via the substrate's at-rest write path are
  never plaintext (the encoding-at-default floor).
- `at_rest::encode_record_content` returns
  `Result<EncodedRecord, CodecError>` (was
  `Result<Option<EncodedRecord>, CodecError>`); the encode seam always
  produces an encoded record.

### default-codec arc (laquna built-in) — Removed

- `NoAtRestHooks` (the no-op baseline the §8.3 generalization introduced
  above). The "no codec installed" semantic no longer exists in the public
  API; operators migrate to `DefaultAtRestHooks::for_data_dir(...)?`.
- `CodecError::NoCodecInstalled` + `CodecErrorClass::NoCodecInstalled` (the
  implementation-cycle gap-fill noted in §8.3 Added above). The scenario is
  structurally impossible via the new public API; cross-codec deployment skew
  is handled by the existing `CodecError::UnknownOrWrongCodec`.

### default-codec arc (laquna built-in) — Documentation

- `ContentCodec` trait rustdoc updated to remove stale "v1 ships no impl" /
  `NoAtRestHooks` references (laquna is the default).
- `DefaultAtRestHooksBuilder::with_codec` rustdoc carries the
  strengthening-only floor reminder.

### §4.3 / §4.5 audience-oracle bind wiring — Changed

- `bind()` now consults the `AudienceOracle` at pipeline stage 3 for every
  capability declaring an `AudienceOracleQuery` (`ViewPrivate`,
  `ParticipatePrivate`, `EditPrivatePost`). A non-`InAudience` result denies the
  bind inline at `PipelineStage::AudienceConsultation`
  (`DenialReason::NotInAudience`, covering both `NotInAudience` and
  `NoAudienceConfigured`); a stale audience oracle (past its
  `data_freshness_bound`, **or future-dated from clock skew** — which fails
  closed rather than reading as fresh) fails closed via the `OracleStale`
  outcome.
  Previously these binds did not consult the oracle, so the per-capability
  predicates were permissive and `ReadAuthorization` — although
  type-state-correct — carried no actual audience check. The per-capability
  `OracleResults` audience field is now `Option<AudienceState>` (default
  `None`); the predicate backstop fails closed on `None`, making an
  unconsulted audience structurally unable to read as a grant. No new
  audit-event, `DenialReason`, or `PipelineStage` variants were required.

### Documentation

- Clarified that the `at_rest::{encode_record_content, decode_record_content}`
  audit emits are **fire-and-forget** (a failing or unavailable audit sink does
  not fail the encode/decode), distinct from the §4.3 capability-bind path where
  audit-unavailable is fail-closed; documented the `MalformedRecordReason`
  codec-orphan vs generation-orphan reporting asymmetry; and documented that the
  `policy.audience` `members` rule binds only under `mode == "list"`.

### Added

- `build.rs` for the kryphocron crate, implementing the §5.4 post-processing
  step that emits per-record-type `HasNsid` impls (each paired with a
  `sealed::Sealed` impl) for every NSID in `KRYPHOCRON_LEXICON_REGISTRY`, with
  the tier taken from the registry entry. Generated into
  `OUT_DIR/has_nsid_impls.rs` and `include!`d from `src/tier.rs`. Also emits
  the `KRYPHOCRON_IMPLEMENTED_NSIDS` constant and a compile-time §5.3
  consistency assertion against `KRYPHOCRON_LEXICON_REGISTRY`; the registry is
  read at build time via a `[build-dependencies]` on `kryphocron-lexicons`.
  Closes the gap where the design-specified post-processing build script was
  never created, leaving the sealed `HasNsid` trait with zero implementors and
  `Tiered<_, _>` uninhabitable for consumers. `tests/has_nsid_impls.rs`
  verifies every record type carries the correct NSID and type-level tier.
- Public `ServiceIdentity::new(service_did, key_id, key_material,
  rotation_evidence)` (`identity.rs`): consumers can now construct their own
  service's audience identity at startup for use as `verify_jwt`'s
  `local_audience`. Adds a public sibling to the `pub(crate)` `new_internal`
  (the redundant `_private: PhantomData` seal is dropped — the struct's private
  fields already block external struct literals). Closes the consumer-side gap
  where the receive-time audience-check requirement
  (`KRYPHOCRON_CRATE_DESIGN.md:6928`) had no public construction path short of
  the `test-support`-gated `new_for_test`, which §0.4 excludes from release
  builds.
- Public `new(...)` constructors on `DidDocument` and `DidService`
  (`resolver.rs`): unblocks operator-implemented `DidResolver`s (the design's
  stated §7.3 extension point) and consumer test fixtures, which must construct
  the values `DidResolver::resolve` returns. `#[non_exhaustive]` is preserved,
  so the substrate keeps the freedom to add fields without breaking external
  consumers. (No `VerificationMethod` constructor: the shipped
  `verification_methods` field is `Vec<(KeyId, PublicKey)>`, not a struct.)
- `tests/public_constructors.rs`: integration tests at the external-crate
  boundary proving the new constructors are reachable by consumers.

### Changed

- Bumped the `kryphocron-lexicons` dependency to consume the 0.2.1
  lexicon-evolution changes: optional `publicCompanion` on
  `postPrivate`; optional `mode`, optional `members`, and optional
  `name` on `policy.audience`; and the `postPrivate.audienceList`
  encoding corrected from a record-def ref to an at-uri string. The
  regenerated `tools::*` codegen types reflect the new optional fields
  and relaxed types; `KRYPHOCRON_CODEGEN_HASH` shifts accordingly.
- No source changes were required in the kryphocron crate. It consumes
  `kryphocron-lexicons` only for the metadata/identifier surface
  (`Tier`, `Visibility`, `UnknownNsid`, `SemVer`, `DeprecationState`,
  `LexiconRegistryEntry`, `KRYPHOCRON_LEXICON_REGISTRY`, the `lexicons()`
  accessor, and the AT-Protocol identifier types) — not the generated
  record structs whose shapes changed. Build and full test suite pass
  against the updated lexicons unchanged.
- No behavioral changes to substrate APIs, capability vocabulary, oracle
  traits, or audit-event vocabulary. `EVENT_SCHEMA_VERSION` unchanged at
  1.0.0.

### Fixed

- `AuthContext<'a>` is now `Send + Sync`. Removed the
  `_no_clone: PhantomData<*const ()>` marker on `ingress.rs` that was meant to
  forbid `Clone` but, as a side effect of the raw pointer's auto-trait
  properties, propagated `!Send + !Sync` — making `AuthContext` (and
  `&AuthContext`) unusable across an `.await` on any executor that requires
  `Send` futures (multi-thread tokio / axum handlers being the canonical case),
  which in turn made the substrate's own async `bind` path (§4.6) unusable from
  such handlers. The type remains `!Clone` because it has no `Clone` impl — the
  marker was redundant for that purpose. Compile-time `Send + Sync` assertions
  added next to the type so a future field addition that reintroduced `!Send`
  fails to compile. No behavioral change. (Sweep confirmed this was the only
  `PhantomData<*const _>` marker in the crate.)

### Docs

- `KRYPHOCRON_CRATE_DESIGN.md` §5.3/§5.4 wording reconciled: per the orphan
  rule, the `HasNsid` impls and `KRYPHOCRON_IMPLEMENTED_NSIDS` are
  kryphocron-crate build outputs, while `KRYPHOCRON_LEXICON_REGISTRY` stays in
  kryphocron-lexicons.
- `KRYPHOCRON_CRATE_DESIGN.md` §7.3 reconciliations: the DID-resolution
  deadline is `verify_jwt`'s `deadline: Instant` parameter (not a
  `JwtVerificationConfig::verification_timeout` field), and `DidDocument` /
  `DidService` ship as `#[non_exhaustive]` with public fields **plus** public
  `new(...)` constructors — realizing the design's consumer-constructible
  intent while preserving field-addition freedom.

## [0.2.0] — 2026-06-02

### Added

- `lexicons()` accessor (re-exported from `kryphocron-lexicons`)
  returning the lexicon document collection for runtime validation,
  suitable for use with `proto_blue_lexicon::validate_record`.
  Additive; `KRYPHOCRON_LEXICON_REGISTRY`, `Tier::from_nsid`, and the
  codegen `tools::*` types are unchanged.

## [0.1.0] — 2026-05-17

Initial publication release. v0.1 ships the kryphocron substrate's
authority discipline end-to-end.

### Added

- §4.3 capability issuance chokepoints: `issue_user`,
  `issue_channel`, `issue_substrate`, `issue_moderation` with
  per-class requester-authority enforcement (substrate /
  moderation are Service-only).
- §4.3 bind + reborrow pipeline across all four capability
  classes (`UserProof`, `ChannelProof`, `SubstrateProof`,
  `ModerationProof`): pre-checks → stage 0 deprecation gate →
  stage 2 oracle consultation (user-class) → stage 5 predicate
  (user-class) → audit emit → stage 6 timing equalization →
  return.
- §4.2 `AuthContext::derive_for` with three legal narrowings:
  `ToAnonymous`, `NarrowCapabilities`, `ServiceToService`.
  Emits `DerivedContext` audit events on every attempt
  (success and failure) via fire-and-forget user-sink
  dispatch.
- §4.1 `tier::visible_to(tier, ctx)` tier × requester-class
  visibility predicate.
- §4.6 `equalize_timing` + `equalize_timing_target_for::<C>`
  (tokio-backed sleep-to-target).
- §4.9 `composite_audit` machinery: class-priority commit
  order (substrate → moderation → user → channel), rollback
  fan-out to already-committed sinks, fallback-sink escalation
  with `catch_unwind` panic catchment.
- §6.7 `InspectionNotificationQueueImpl` trait + the
  `NoInspectionNotifications` no-op default for moderation-
  class inspection-notification fan-out (outside composite-
  rollback semantics).
- `ingress::AuditSinks` fields: `inspection_queue` (§6.7
  emission) and `correlation_key` (§4.4 session-digest
  computation).
- `HasResourceLocation` sealed trait surface for stage 0
  deprecation-gate NSID extraction (implemented on
  `ResourceId`, `ManageAudienceSubject`, `ModerationSubject`).
- `RequesterKind` discriminator + `Requester::kind()` accessor
  for forensic-clear stage 1 issuance diagnostics.
- `AuthDenial::RequesterLacksAuthority { class, found }`
  variant.
- `DenialReason::CapabilityDeprecated { nsid, since_version,
  successor }` and `BindError::DeniedAtPipeline { stage,
  reason }` variants for §4.3 bind stage failures.
- `From<CompositeAuditError> for BindError` for `?`-propagation
  of audit-machinery failures into the bind-error channel.
- `ingress::anonymous_for_public_read(trace_id, sinks,
  oracles)` public constructor.
- Publication-quality README + crate-root rustdoc covering
  the wired surface.

### Changed

- All `*Proof::bind` and `Bound*Proof::reborrow` methods are
  now `async fn` (the §4.3 pipeline runs inside
  `composite_audit` which is async).
- `derive_for<N: Narrowing>` gained a `+ 'static` bound on `N`
  to enable internal `Any`-based narrowing dispatch (v1's
  three impls already satisfy).
- `ingress::anonymous_for_public_read` signature added a
  `trace_id` parameter (callers now supply per-request trace
  ids matching the other ingress constructors).
- License swapped from previous placeholder to MPL-2.0 (crate
  code). Per-file MPL-2.0 headers added to all `src/*.rs`.
  Companion `kryphocron-lexicons` crate ships under
  `MPL-2.0 AND CC0-1.0` (Rust wrappers MPL-2.0, lexicon JSON
  CC0-1.0).
- Cargo.toml metadata polished for crates.io publication;
  version bumped from `0.1.0-phase1` to `0.1.0`.
- `tokio` promoted from a dev-only dependency to a production
  dependency with the `time` feature (§4.6 timing-channel
  equalization uses `tokio::time::sleep`). Operators on a
  non-tokio async runtime supply a tokio-compatible reactor or
  shim.
- `publish = false` removed.

### Removed

- `from_sync_channel_handshake` placeholder constructor and
  `VerifiedHandshake` placeholder type. Both were unwired
  pre-v0.1 surfaces; superseded by the three-message
  sync-handshake protocol (`VerifiedSyncHello`,
  `VerifiedSyncAccept`, `VerifiedSyncEstablished`) +
  post-handshake `VerifiedSyncMessage` shipped with the
  inter-service auth surfaces.
- `construct_user_proof` thin wrapper around
  `UserProof::new_internal`. Subsumed by `issue_user`'s direct
  call to the constructor.

### Notes

`ModerationProof::bind` takes a fourth `rationale:
ModeratorRationale` argument (the other three classes' bind
methods take `(self, ctx, target)` only). The asymmetry is
intentional: rationale is bind-time input matching operator
workflows, not issuance-time input. Operators writing generic
bind-dispatch code need to handle this asymmetry. See README
"Bind API asymmetry" subsection.

Several audit-event payload fields ship with placeholder data
in v0.1 pending sealed per-class extraction traits (channel-
class peer + session id, substrate-class scope kind,
moderation-class case id). The `composite_audit` emission
semantics are exercised end-to-end; the audit-event forensic
detail is degraded for non-user classes. See README "v0.1
enrichment posture" section.

Wire-format-touching changes are reserved for a future v0.2 or
v1.0 cycle. v0.1.x patches are non-breaking only.

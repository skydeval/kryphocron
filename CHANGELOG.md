# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.4.3] — 2026-10-21

Patch release. No API change. Records written by 0.4.3 decode with earlier
0.4.x releases, and earlier records decode with 0.4.3.

### Fixed

- The laquna codec took its slug from the rotation generation, so every
  encode in one generation window shared a slug. Its seed is fixed per record
  identity (DID, NSID, rkey), so two different contents encoded at the same
  identity in one window — a record deleted and re-created at the same rkey —
  shared a keystream, and anyone holding both artifacts could combine them.
  `laquna::Codec` now draws a fresh 32-byte CSRNG slug for every encode. The
  slug still travels in the artifact, where decode reads it.

### Changed

- Encoding is no longer deterministic: encoding the same content twice gives
  different bytes. Compare records by `encodedContentGeneration` or by decoded
  content, not by encoded bytes.
- The generation mark stamped on each record is unchanged and is still what
  rotation keys on, but its batch id is no longer the artifact's slug. Nothing
  should compare the two.
- `laquna::Codec` no longer reads anything from the generation mark, so a
  rotation oracle with a different mark format no longer panics on encode.
  CSRNG failure on encode returns `CodecError::BackendUnavailable`.

## [0.4.2] — 2026-10-21

Patch release. Additive only: existing callers behave exactly as before.

### Added

- `laquna::Codec::with_max_decoded_len(n)` and `Codec::max_decoded_len()`: an
  optional, caller-chosen bound on decoded size. Unbounded by default; the
  substrate sets no value, since the right one is host policy. Hosts that
  decode records written by parties they do not trust should set one and
  install the codec via `DefaultAtRestHooksBuilder::with_codec`.

  Without a bound, a small crafted record (zstd RLE blocks, or a frame
  declaring a large window) can decompress to gigabytes before the checksum is
  checked. With a bound, a frame whose header declares a content size or
  window over it is refused before any block is decoded, and decoding stops as
  soon as output passes it. Either case fails as `CodecError::Malformed`, and
  peak memory stays within a small multiple of the bound.

## [0.4.1] — 2026-10-18

Patch release. No API change: inputs that used to panic now return the
decoder's existing error.

### Fixed

- `verify_jwt` panicked ("overflow when adding duration to instant") on a
  correctly signed token whose `exp`, `iat` or `nbf` exceeds the platform's
  `SystemTime` range, and on an `exp` close enough to that maximum that adding
  `max_clock_skew` overflowed. Any issuer able to sign for its own DID could
  trigger it. All four cases now return `JwtVerificationError::Malformed`; an
  out-of-range `nbf` is `Malformed`, not treated as absent.
- The same overflow in the CBOR time decoders for trust declarations
  (`TrustDeclarationError::Malformed`) and for peer-supplied sync-handshake and
  capability-claim wire messages (decode error), and in the laquna rotation
  oracle's state-file reader (treated as an unreadable state file; a fresh
  batch starts instead of a crash at startup).

## [0.4.0] — 2026-09-25

0.4.0 is a minor-version (breaking under 0.x) release because
`DidDocument`'s key fields and `DidDocument::new` change type (see Changed).
The substrate-internal `PublicKey`, `ServiceIdentity`, and both wire formats
are unchanged.

### Added

- ATProto service-auth JWT verification end to end: `verify_jwt` now verifies
  ES256K / ES256 tokens issued by real did:plc / did:web identities (the
  resolver parses their secp256k1 / P-256 keys, see Changed).
- `JwtVerificationConfig::atproto_service_auth()` and
  `verification::ATPROTO_SERVICE_AUTH_ALGORITHMS` (`[Es256K, Es256]`). The
  `Default` allowlist stays Ed25519-only; ATProto-facing hosts opt in.
- `VerifiedJwt::lxm() -> Option<&str>` — the ATProto lexicon-method claim.
  `verify_jwt` extracts it (a non-string `lxm` is `Malformed`) but does not
  interpret it; the host compares it against the method being served.
- `VerifiedJwt::audience_fragment() -> Option<&str>` — the `#fragment` of a
  DID-URL `aud`, for hosts serving several services under one DID.
- Fragment-tolerant `aud`: `verify_jwt` accepts `aud` equal to the local
  service DID or `<local service DID>#<fragment>` (the form ATProto clients
  use when proxying to a named service, e.g. `#bsky_appview`). Any non-empty
  fragment is accepted; an empty fragment (`<did>#`) is `Malformed`; a
  different DID with any fragment is `WrongAudience`.
- ES256 / ES256K JWT signature verification (`verification.rs`) on RustCrypto's
  `k256` (secp256k1) and `p256` (P-256). Pure-Rust, no FFI, no OpenSSL —
  preserves the substrate's static-musl-friendly posture. Closes the deferred
  ECDSA gap that limited authenticated-path testing to Ed25519-only synthetic
  tokens; the forward-looking `SignatureAlgorithm` allowlist (`Es256K`, `Es256`,
  `Ed25519`) now has matching verification logic for all three.
- `identity::IssuerPublicKey` enum decoupling the DID-document / JWT-issuer key
  population from the substrate-internal `PublicKey`. Variants:
  `Ed25519([u8;32])`, `Secp256k1(Vec<u8>)`, `P256(Vec<u8>)`; SEC1 compressed (33)
  and uncompressed (65) both accepted, stored as received. `#[non_exhaustive]`
  for future algorithms. Re-exported at the crate root.
- Strict low-S signature rejection on both ECDSA verifiers (ATProto canonicality
  + signature-malleability resistance): `Signature::normalize_s().is_some()`
  detects high-S, rejected via the new `JwtVerificationError::HighSSignature`
  variant. JWS signatures parse as fixed `r‖s` (64 bytes), not ASN.1 DER
  (`Signature::from_slice`).
- ES256/K signed-JWT fixtures via the existing `test-support` feature
  (`identity::fixtures::{secp256k1_signing_pair, p256_signing_pair,
  sign_jwt_es256k, sign_jwt_es256}`). §0.4 keeps them compile-excluded from
  release builds; downstream consumers enable the feature in `[dev-dependencies]`
  only.

### Changed

- `DidDocument.verification_methods` and `rotation_history` carry
  `Vec<(KeyId, IssuerPublicKey)>` (was `Vec<(KeyId, PublicKey)>`);
  `DidDocument::new`'s public signature adjusts. The substrate-internal
  `PublicKey`, `ServiceIdentity`, and the §4.8 capability-claim + §7.5
  sync-handshake wire formats are **unchanged** — the decoupling localizes the
  widening to the issuer-key path via an `extract_ed25519_pubkey` adapter at the
  wire-path selector boundaries (substrate service keys are always Ed25519). The
  adapter is applied at four `verification_methods` consumers: the JWT selector
  (returns `IssuerPublicKey`) plus the capability-claim, sync-handshake, and
  attribution-chain-receipt selectors (each extracts an Ed25519 `PublicKey`).
- `DefaultDidResolver` DID-document parsing reads the multicodec prefix of
  `publicKeyMultibase` and produces the matching `IssuerPublicKey`:
  `0xed 0x01` ed25519-pub (32 bytes), `0xe7 0x01` secp256k1-pub and
  `0x80 0x24` p256-pub (33-byte compressed SEC1). Covers the `Multikey` type
  (and `Ed25519VerificationKey2020` / untyped entries, as before) plus the
  legacy ATProto `EcdsaSecp256k1VerificationKey2019` /
  `EcdsaSecp256r1VerificationKey2019` forms (raw SEC1, no multicodec prefix).
  ECDSA keys are checked to be valid curve points at parse time.
- Behavior change: a verification method with an unsupported type, encoding,
  curve, or an invalid key is now **skipped** instead of failing the whole
  document as `DidResolutionError::Malformed`. Previously any non-Ed25519 key —
  i.e. every did:plc `#atproto` key — made the document unresolvable. A
  document with no usable key surfaces at the verifier as its key-not-found
  error. An entry missing `id` is still `Malformed`.
- The `#atproto` verification method is ordered first in
  `DidDocument.verification_methods`, so `verify_jwt`'s no-`kid` selection
  (first key matching the JWT algorithm — the ATProto service-auth norm) picks
  the account signing key ahead of other same-curve keys such as a labeler's
  `#atproto_label`.
- `JwtVerificationError`: new `HighSSignature` variant (the enum is
  `#[non_exhaustive]`). All other ECDSA failure modes — malformed key, malformed
  signature, wrong-algorithm-on-key, verify-fail — consolidate into the existing
  `SignatureInvalid` per the established convention (no four-variant expansion).

### Dependencies

- `k256 = "~0.13"` (ecdsa feature, default-features off) — secp256k1 / ES256K.
- `p256 = "~0.13"` (ecdsa feature, default-features off) — P-256 / ES256.
  Both RustCrypto, pure-Rust, no FFI; integrate via `signature::Verifier`
  matching `ed25519-dalek 2.x`. `cargo tree -i openssl-sys` / `-i native-tls`
  remain empty.

### Tests

- End-to-end `verify_jwt` coverage for ES256K / ES256: valid token accepted,
  high-S rejected, wrong key rejected; allowlist filtering in each direction;
  `lxm` present / absent / non-string; `aud` exact, `#fragment` on the local
  DID (any fragment), fragment on another DID, empty fragment; Ed25519
  regression (no `lxm` / fragment surfaced).
- Resolver Multikey coverage: secp256k1, P-256, Ed25519 prefixes; the ATProto
  cryptography spec's example `did:key` multibase values; legacy ECDSA types;
  `#atproto` ordering; unknown prefix / wrong length / off-curve point /
  unsupported type / non-base58btc entries skipped without failing the
  document.
- `ecdsa_verifier_tests` module in `verification.rs` (13 tests): happy-path,
  wrong-signature, malformed-key, wrong-algorithm-on-key, high-S rejection, and
  compressed-vs-uncompressed SEC1 acceptance for each of ES256K and ES256, plus
  an `extract_ed25519_pubkey` regression guard (Ed25519 accepted; ECDSA
  variants rejected) for the substrate-Ed25519 wire-path invariant. Signing is
  inline (no `test-support` needed for the in-crate suite); high-S signatures
  are built by `n − s` complement so the test is independent of the ECDSA
  crates' scalar API.

## [0.3.1] — 2026-06-16

### Added

- `encryption::EncodedRecord::new(codec, content, generation)` — host-
  constructible at-rest decode input, mirroring the encode-side
  `at_rest::RecordContentContext::new`. Hosts rebuild an `EncodedRecord` from
  persisted lexicon field values (`encodedContent`, `encodedContentCodec`,
  `encodedContentGeneration`) before passing it to
  `at_rest::decode_record_content` / `ContentCodec::decode`.
- `encryption::DecodeContext::new(nsid, rkey, originator, audience_list,
  trace_id, operator_context)` — host-constructible decode context, completing
  the symmetry between encode and decode at the host-API surface.
- `VERSION` — the substrate crate-version static (`env!("CARGO_PKG_VERSION")`),
  for consumer identity surfaces (dashboards, logs, audit headers).
- `audit::AUDIT_EVENT_TYPES` (re-exported as `AUDIT_EVENT_TYPES` at the crate
  root) — enumeration of the substrate audit-event type names, keyed to
  `audit::EVENT_SCHEMA_VERSION`, for consumer audit-vocabulary tooling. Covers
  all five §6 audit-event enums (`UserAuditEvent`, `ChannelAuditEvent`,
  `SubstrateAuditEvent`, `ModerationAuditEvent`, `FallbackAuditEvent`); each
  entry is the `<Enum>::<Variant>` path so the recurring
  `CompositeRollbackMarker` variant stays unambiguous.

### Notes

- This is a purely additive patch: no breaking changes, no behavior changes, no
  field exposure beyond the new public constructors. The `#[non_exhaustive]`
  attributes on `EncodedRecord` and `DecodeContext` remain — only public
  construction is added, not full struct exposure.
- The encode/decode asymmetry at the host-API surface (encode returned
  `EncodedRecord` to the host; decode required the host to construct one but
  exposed no constructor) was a 0.3.0 oversight surfaced by first-adopter
  integration findings. 0.3.1 closes it.

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

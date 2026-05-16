# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] — 2026-05-15

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
  `VerifiedHandshake` placeholder type. Both were Phase 1
  surfaces never wired; superseded by the three-message
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

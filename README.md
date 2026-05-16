# kryphocron

**Privacy-first ATProto substrate primitives.** Type architecture,
audit vocabulary, inter-service auth, and encryption hooks for
substrates that need to commit threat-model invariants
structurally rather than as policy.

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen.svg)](https://www.mozilla.org/MPL/2.0/)
[![Crates.io](https://img.shields.io/crates/v/kryphocron)](https://crates.io/crates/kryphocron)

## What it is

`kryphocron` is the foundational primitives crate for the
Kryphocron substrate — an ATProto-compatible identity and
publishing substrate built around the discipline that **the
wrong path is harder to write than the right path**. Misuse of
a primitive should be a compile error wherever possible, a
runtime error otherwise, and a silent success never.

The crate ships:

- **Tier-aware envelope types** (`Tier`, `Tiered<T>`, `HasNsid`)
  that make Public / Private classification a structural
  property of the type system. A function emitting to a public
  surface cannot, by type, accept a private-tier value.
- **Capability proofs** — sealed, unforgeable in safe Rust via
  `PhantomData<sealed::Token>` markers.
- **`AuthContext`** — the in-process authentication context
  type with attribution-chain rehydration from upstream
  delegation.
- **Audit pipeline** — composite-rollback machinery, fallback-
  sink contract, and a 30+ variant audit-event vocabulary
  covering user, channel, substrate, and moderation classes.
- **Inter-service auth** — JWT verification, capability claim
  wire format with W11/W12/W13 monotonicity invariants, trust
  declarations, DID resolution, and the three-message sync
  handshake protocol.
- **Encryption hook surfaces** — operator-pluggable
  `AuditEncryptionResolver` and `RecordEncryptionResolver`
  trait shapes; v1 ships the surfaces, v2+ ships the algorithm
  variants.

## What it is NOT

`kryphocron` deliberately does NOT ship:

- Concrete encryption implementations. The trait surfaces are
  committed; specific ciphers are operator-supplied.
- A PDS, AppView, Graph, or any other operator substrate
  component. Those are downstream crates that build on
  kryphocron primitives.
- HTTP transport, TLS, or wire I/O. The crate produces and
  consumes byte arrays; operators wire up their own transports.
- Key management, KMS integrations, or rotation orchestration.
  The crate's `DidResolver` and encryption resolvers receive
  key material from operator code.
- ATProto record validation beyond what `kryphocron-lexicons`
  commits.

The discipline is **door-open, not door-ajar**: where an
implementation choice is operator policy, the crate commits a
trait shape and leaves the implementation to operators.

## Quick start

```toml
[dependencies]
kryphocron = "0.1"
```

A minimal substrate-side integration sketch:

```rust,ignore
use kryphocron::{
    AuditSinks, NoEncryption, OracleSet, TraceId,
    authority::{NoInspectionNotifications, issue_user, v1::ViewPrivate},
    verification::verify_jwt,
};

// At substrate startup, install audit sinks, oracles, the DID
// resolver, the deployment correlation key, the inspection-
// notification queue, and (optionally) an encryption resolver set.
let resolver_set = NoEncryption;  // v1 default; no encryption.
let inspection_queue = NoInspectionNotifications;  // no-op default.

// Per-request: verify a JWT, build an AuthContext.
let trace_id = TraceId::from_bytes(/* fresh per-request */);
let verified = verify_jwt(
    authorization_header,
    &local_audience,
    &did_resolver,
    &jwt_config,
    deadline,
    trace_id,
).await?;
let ctx = kryphocron::ingress::from_xrpc_request(
    verified, trace_id, sinks, oracles,
);

// Issue a capability proof against the requester's context, then
// bind it against the target. `bind` and `reborrow` are async —
// the §4.3 pipeline runs inside `composite_audit` which is
// async, and timing-channel equalization sleeps via tokio.
let proof = issue_user::<ViewPrivate>(&ctx, target_resource_id)?;
let bound = proof.bind(&ctx, &target_resource_id).await?;

// `bound` grants access to the subject; the audit pipeline has
// already fired the terminal CapabilityBound event structurally.
let subject = bound.subject();
```

The substrate's value isn't in the API ergonomics — it's in the
threat-model invariants the type system enforces.

### Bind API asymmetry

Three of the four `*Proof::bind` methods take `(self, ctx, target)`.
`ModerationProof::bind` takes a fourth argument:
`rationale: ModeratorRationale` (a length-bounded operator-declared
string, mandatory for every moderation action per §6.5). Operators
writing generic bind-dispatch code need to handle this asymmetry —
the rationale is bind-time input, not issuance-time, matching
operator workflows where the moderator commits a rationale at
the moment of action.

## Design discipline

Five organizing principles:

1. **The wrong path is harder to write than the right path.**
   Misuse of a primitive is a compile error wherever possible,
   a runtime error otherwise, and a silent success never.

2. **Capabilities are unforgeable in safe code.** Code outside
   the crate's `authority` module cannot construct authorization
   proofs. Sealed traits and a private token type carried in
   `PhantomData` on every proof type enforce this.

3. **Tier is not a label, it's a structural property.** A
   function that emits to a public surface cannot accept a
   private-tier value, by type, not by runtime check.

4. **Audit reflects action, not intent.** Audit events fire on
   the *binding* of a capability proof (success or failure), not
   on its issuance.

5. **Door-open, not door-ajar.** Where the spec defers a choice
   to operator policy, the crate commits the trait surface and
   leaves the implementation pluggable. Defaults are explicit
   (e.g., `NoEncryption` for the encryption resolver set), not
   implicit.

## Status

**v0.1.0** ships the kryphocron substrate's authority discipline
end-to-end:

- **§4 type architecture** — tier-aware envelopes, sealed
  capability proofs (no struct-literal construction outside the
  crate), `AuthContext` with attribution-chain rehydration from
  upstream delegation.
- **§4.1 tier-aware visibility** — `tier::visible_to(tier, ctx)`
  predicate.
- **§4.2 scope-narrowing derivation** — `AuthContext::derive_for`
  with three legal narrowings (drop-to-anonymous,
  narrow-capabilities, service-to-service); audit emits a
  `DerivedContext` event on every attempt (success and failure).
- **§4.3 capability issuance** — `issue_user`, `issue_channel`,
  `issue_substrate`, `issue_moderation` chokepoints with
  per-class requester-authority enforcement.
- **§4.3 bind + reborrow** — async pipelines across all four
  capability classes: pre-checks → stage 0 deprecation gate
  (write-semantics user-class + moderation) → stage 2 oracle
  consultation (user-class) → stage 5 predicate (user-class) →
  audit emit via `composite_audit` → stage 6 timing equalization
  (user-class) → return.
- **§4.6 timing-channel equalization** — `equalize_timing` +
  `equalize_timing_target_for::<C>` via `tokio::time::sleep`.
  Coarse equalization to a deployment-configured target;
  **NOT** a constant-time discipline. Granularity is limited by
  the host scheduler (ms-scale jitter on Windows/WSL; tighter on
  Linux), and a network-side adversary with high-resolution
  latency measurement can still see through the equalization for
  short-running operations. Operators with strong timing-channel
  threat models should treat this as a coarse first defense and
  layer constant-time-discipline cryptographic primitives + a
  hardened timing primitive (e.g. randomized jitter, ring-buffered
  release queues) at the perimeter. Full hardening is v2+ work.
- **§4.9 composite-audit machinery** — class-priority commit
  order (substrate → moderation → user → channel), rollback
  fan-out to already-committed sinks, fallback-sink escalation
  with `catch_unwind` panic catchment.
- **§5 lexicon strategy** — closed-namespace registry via the
  companion `kryphocron-lexicons` crate; `Tier::from_nsid`
  consults the build-time-authoritative
  `KRYPHOCRON_LEXICON_REGISTRY`.
- **§6 audit event vocabulary** — 30+ variants across user,
  channel, substrate, moderation classes; encrypted-layer split
  via `TargetRepresentation::structural_only` /
  `TargetRepresentation::with_sensitive`.
- **§6.7 inspection-notification queue** — moderation-class fan-
  out alongside the composite-audit emission; outside rollback
  semantics per the "notifications are diagnostic, not
  authoritative" discipline.
- **§7 inter-service auth** — JWT verification (Ed25519 default;
  ECDSA recognized but not v1-shipped), `CapabilityClaim` wire
  format with W11/W12/W13 monotonicity invariants, trust
  declarations, DID resolution + rotation evidence, three-message
  sync handshake protocol, delegation receipts + chain
  rehydration.
- **§8 encryption hook surfaces** — `AuditEncryptionResolver`,
  `RecordEncryptionResolver` trait shapes; v1 default is
  `NoEncryption` (no-op resolver set), operator plug-ins fill
  in real algorithm support.

### v0.1 enrichment posture

The audit pipeline is wired end-to-end. A few audit-event
payload fields ship with placeholder data in v0.1 pending
sealed per-class extraction traits in v0.2:

- Channel-class `peer ServiceIdentity` and `session_id`.
- Substrate-class `scope_repr`.
- Moderation-class `case ModerationCaseId`.

User-class oracle consultations consult only the universal
block-vs-resource-owner query in v0.1 (multi-query consultations
land alongside a per-capability oracle-results-builder in v0.2).
`tier::visible_to` is tier-only in v0.1; an audience-aware
overload lands in v0.2.
Moderation-class reborrow miss is silent at the audit layer in
v0.1 (no fitting variant in v1's audit vocabulary); v0.2 adds
the variant.

Wire-format-touching changes are reserved for a future v0.2 or
v1.0 cycle. v0.1.x patches are non-breaking only.

## License

**MPL-2.0** (Mozilla Public License 2.0). See `LICENSE`.

The MPL is file-level copyleft: modifications to MPL-2.0-licensed
source files must be released under MPL-2.0; downstream crates
linking to `kryphocron` are unconstrained and may ship under
permissive licenses (MIT OR Apache-2.0 recommended for operator
substrate components like PDS, AppView, etc.).

The companion `kryphocron-lexicons` crate ships its lexicon JSON
files under CC0-1.0 (public domain dedication); the wire
vocabulary is universal and unencumbered.

## Project shape

Kryphocron is a privacy-first ATProto substrate by @skydeval.
The crate is MPL-2.0; the companion lexicon JSON is CC0-1.0.
See LICENSE for the full text.

## Related

- `kryphocron-lexicons` — companion crate shipping the v1
  lexicon JSON + Rust codegen wrappers. Required for
  consumers using lexicon-validated record types.

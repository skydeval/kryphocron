# kryphocron

**Privacy-first ATProto substrate primitives.** Type architecture,
audit vocabulary, inter-service auth, and at-rest content encoding for
substrates that need to commit threat-model invariants structurally
rather than as policy.

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen.svg)](https://www.mozilla.org/MPL/2.0/)
[![Crates.io](https://img.shields.io/crates/v/kryphocron)](https://crates.io/crates/kryphocron)

## What it is

`kryphocron` is the foundational primitives crate for the Kryphocron
substrate — an ATProto-compatible identity and publishing substrate built
around the discipline that **the wrong path is harder to write than the right
path**. Misuse of a primitive should be a compile error wherever possible, a
runtime error otherwise, and a silent success never.

The crate ships:

- **Tier-aware envelope types** (`Tier`, `Tiered<T>`, `HasNsid`) that make
  Public / Private classification a structural property of the type system. A
  function emitting to a public surface cannot, by type, accept a private-tier
  value.
- **Capability proofs** — sealed, unforgeable in safe Rust via
  `PhantomData<sealed::Token>` markers.
- **`AuthContext`** — the in-process authentication context type with
  attribution-chain rehydration from upstream delegation.
- **Audit pipeline** — composite-rollback machinery, a fallback-sink contract,
  and a 30+ variant audit-event vocabulary covering user, channel, substrate,
  and moderation classes.
- **Inter-service auth** — JWT verification, a capability-claim wire format
  with monotonicity invariants (replay / time-rewind guards), trust
  declarations, DID resolution, and the three-message sync handshake.
- **At-rest content codec** — private-tier record content is **encoded at rest
  by default** via the `ContentCodec` seam, with the friction-encoding
  `laquna` codec shipped as the built-in `DefaultAtRestHooks` baseline.
  Operators may substitute a *strengthening* codec (authenticated encryption,
  HSM-backed). See "Privacy posture".
- **Audit-encryption hook surface** — the operator-pluggable
  `AuditEncryptionResolver` trait shape; the crate ships the surface, operator
  plug-ins fill in algorithm variants.

## What it is NOT

`kryphocron` deliberately does NOT ship:

- Confidentiality-grade encryption. The default at-rest codec (laquna) is
  *friction-encoding*, explicitly not encryption (see Privacy posture); the
  `ContentCodec` seam accepts an operator-supplied authenticated-encryption
  codec, but the crate ships no cipher of its own.
- A PDS, AppView, or any other operator substrate component — those are
  downstream crates that build on kryphocron primitives.
- HTTP transport, TLS, or wire I/O. The crate produces and consumes byte
  arrays; operators wire up their own transports.
- Key management, KMS integrations, or multi-process rotation coordination.
  The crate ships a **single-process** `DefaultRotationOracle`; coordinated
  (DB/KMS-backed) rotation is operator-supplied, and the `DidResolver` and
  audit-encryption resolver receive key material from operator code.
- ATProto record validation beyond what `kryphocron-lexicons` commits.

The discipline is **door-open, not door-ajar**: where an implementation choice
is operator policy, the crate commits a trait shape and leaves the
implementation to operators. The at-rest content codec is the one principled
exception — encoding-at-default, not door-open (see Privacy posture below).

## Privacy posture

kryphocron stores private-tier records encoded at rest by default,
using a friction-encoding codec (laquna) shipped as part of the
substrate. From laquna's README:

> Laquna is not encryption. The decoder is in this repository, the
> slug travels inline in every artifact, and the seed is typically
> derived from public metadata, so any party with this code and the
> seed can recover the plaintext. Laquna provides no confidentiality,
> no authentication, and no resistance to a motivated adversary. Its
> only value is friction against opportunistic, at-scale content
> extraction.
>
> Laquna provides friction against opportunistic and determined human
> adversaries. It does not defend against LLM-assisted adversaries
> that can call the public `decode()` API directly; consumers requiring
> resistance to LLM-assisted bulk extraction must compose Laquna with
> additional access controls in the consuming system.

Operators requiring stronger at-rest guarantees install an alternative
`ContentCodec` via custom `AtRestHooks`. The substrate's encode/decode
seams accept any codec implementation that satisfies the `ContentCodec`
trait — including authenticated encryption codecs that deliver
confidentiality and integrity. **Substitution is a strengthening path;
configurations that opt out of encoding-at-rest (identity codecs, no-op
encoders) are not supported. Kryphocron's identity is
encoding-at-default — deployments configured otherwise are not
kryphocron deployments.**

Note on layered privacy: the substrate's audience-oracle wiring is the
**authorization** layer — it gates *who can read* a record.
Friction-encoding is the **at-rest** layer — it raises the cost of
*unauthorized observation of repository bytes*. The two layers compose:
audience-enforced read authorization plus friction-encoded at-rest
storage. Neither alone is sufficient for strong privacy; together they
form kryphocron's defense-in-depth posture.

### Deployment shape and the default rotation oracle

The substrate ships `DefaultRotationOracle` as part of
`DefaultAtRestHooks` — a **single-process** rotation oracle. It uses a
file-backed generation state at `<data_dir>/kryphocron/rotation.state`
and is correct under deployments where exactly one kryphocron process
touches the data dir at a time.

**Multi-process deployments — including any deployment behind a load
balancer with multiple workers, deployments with separate writer and
reader processes, deployments with maintenance workers (compactors,
re-encoding jobs, audit scrubbers) alongside the main service, and
deployments using process supervisors that may briefly run two copies
during restart — install a coordinated `RotationOracle` (DB-backed,
KMS-backed, or otherwise process-coordinated) from day one, not "as
they scale."** This applies regardless of user count.

Records are encoded under both single- and multi-process configurations
— encoding-at-default holds either way. What `DefaultRotationOracle`
delivers under single-process deployment is the
rotation-cadence-correct-over-time property; multi-process deployments
running `DefaultRotationOracle` get encoded records but with
process-divergent rotation state, which silently breaks the
rewrite-on-rotate mechanism the substrate ships to refresh friction.
Substituting a coordinated oracle restores correctness.

## Quick start

```toml
[dependencies]
kryphocron = "0.3"
```

A minimal substrate-side integration sketch:

```rust,ignore
use kryphocron::{
    AuditSinks, DefaultAtRestHooks, OracleSet, TraceId,
    authority::{NoInspectionNotifications, issue_user, v1::ViewPrivate},
    verification::verify_jwt,
};

// At substrate startup, install audit sinks, oracles, the DID
// resolver, the deployment correlation key, and the inspection-
// notification queue.
let inspection_queue = NoInspectionNotifications;  // no-op default.

// Private-tier record content is encoded at rest by default. Construct the
// baseline at-rest hooks once at startup; the
// `at_rest::{encode,decode}_record_content` seams drive the installed
// `ContentCodec` (laquna by default). See "Privacy posture" above.
let at_rest_hooks = DefaultAtRestHooks::for_data_dir(data_dir)?;

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
// the bind pipeline runs inside `composite_audit`, which is async,
// and timing-channel equalization sleeps via tokio.
let proof = issue_user::<ViewPrivate>(&ctx, target_resource_id)?;
let bound = proof.bind(&ctx, &target_resource_id).await?;

// `bound` grants access to the subject; the audit pipeline has
// already fired the terminal CapabilityBound event structurally.
let subject = bound.subject();
```

The substrate's value isn't in the API ergonomics — it's in the threat-model
invariants the type system enforces.

### Bind API asymmetry

Three of the four `*Proof::bind` methods take `(self, ctx, target)`.
`ModerationProof::bind` takes a fourth argument: `rationale:
ModeratorRationale` (a length-bounded operator-declared string, mandatory for
every moderation action). Operators writing generic bind-dispatch code must
handle this asymmetry — the rationale is bind-time input, not issuance-time,
matching workflows where the moderator commits a rationale at the moment of
action.

## Design discipline

Five organizing principles:

1. **The wrong path is harder to write than the right path.** Misuse of a
   primitive is a compile error wherever possible, a runtime error otherwise,
   and a silent success never.
2. **Capabilities are unforgeable in safe code.** Code outside the crate's
   `authority` module cannot construct authorization proofs — sealed traits
   and a private token carried in `PhantomData` on every proof type enforce
   this.
3. **Tier is not a label, it's a structural property.** A function emitting to
   a public surface cannot accept a private-tier value, by type, not by
   runtime check.
4. **Audit reflects action, not intent.** Audit events fire on the *binding*
   of a capability proof (success or failure), not on its issuance.
5. **Door-open, not door-ajar.** Where an implementation choice is operator
   policy, the crate ships the trait surface and leaves the implementation
   pluggable. Defaults are explicit (e.g. `NoInspectionNotifications`), not
   implicit. The at-rest content codec is the one principled exception —
   encoding-at-default, not door-open (see Privacy posture).

## Status

0.3.0 ships the substrate's authority discipline end-to-end: tier-aware
envelopes, sealed capability proofs, the `AuthContext` derivation surface, the
audit pipeline with composite-rollback machinery, JWT-based inter-service auth
with the three-message sync handshake, and the at-rest content-codec seam with
the built-in `laquna` default. 390+ tests pin behavior across all four
capability classes plus the timing-channel equalization surface; the crate
forbids `unsafe` and denies `todo!()` / `unimplemented!()`.

Audiences: ATProto-adjacent operators evaluating whether the substrate's design
fits their threat model; downstream integrators (PDS, AppView, Graph
substrates) consuming kryphocron as a dependency; and adversarial reviewers
stress-testing the threat-model commitments. Wire-format and audit-event shapes
are committed within 0.3.x; consumer-facing API ergonomics may still evolve.

### Known limitations

None of these are security bugs — they're places where the current surface is
narrower than the full design commitment, with the gap closed in future
enrichment passes.

**Coarse timing equalization.** `equalize_timing` equalizes to a
deployment-configured target via a sleep primitive; it is **not** a
constant-time discipline. Granularity is bounded by the host scheduler
(ms-scale jitter on Windows/WSL, tighter on Linux), and a network adversary
with high-resolution latency measurement can see through it for short
operations. Treat it as a coarse first defense and layer constant-time crypto
primitives + a hardened timing primitive at the perimeter for strong
timing-channel threat models.

**Placeholder audit-event payloads.** A few audit-event fields ship with
placeholder data pending sealed per-class extraction traits: channel-class
`peer` / `session_id` (`ChannelBound` / `ChannelReborrowFailed`),
substrate-class `scope_repr` (`ScopeBound`), and moderation-class case id
(`ModeratorInspected` / `ModeratorTookDown` / `ModeratorRestored`). These
variants carry a `payload_completeness` field set to `PartialV01`; a future
release flips it to `Full`. Consumers branch on it to avoid rendering
placeholder data as real values.

**Deferred enrichments.** User-class bind consults the block-vs-resource-owner
query and (for audience-gated capabilities) the audience oracle; a generalized
per-capability multi-query oracle-results-builder is future work.
`tier::visible_to` is tier-only — an audience-aware overload is future work
(bind itself consults the audience oracle, so the gap is limited to the
standalone predicate). Moderation-class reborrow miss is silent at the audit
layer (no fitting variant yet); a future release adds it.

Wire-format-touching changes are reserved for a future minor cycle or the v1.0
cycle. v0.3.x patches are non-breaking only.

### Closed-namespace lexicon registry

kryphocron's tier classification is closed-namespace: only NSIDs in the
`tools.kryphocron.*` namespace are known to the registry. `Tier::from_nsid`
consults `KRYPHOCRON_LEXICON_REGISTRY` and returns
`Err(UnknownNsid::NotRegistered)` for NSIDs outside it — including
ATProto-ecosystem NSIDs like `app.bsky.feed.post`. **There is no
default-to-`Tier::Public`**; unknown NSIDs are a hard error, not a permissive
fallback.

Operators running kryphocron alongside other ATProto lexicons (e.g. a PDS
handling both `app.bsky.*` and `tools.kryphocron.*` records) must handle
non-kryphocron records via their own classification or routing — kryphocron's
tier discipline applies only to its own namespace. Cross-namespace
classification is reserved for a future release if operators surface demand.

## Feedback and contributing

Three channels, sorted by what you have:

- **Integration pain or substrate-side bug** → open a GitHub issue at
  <https://github.com/skydeval/kryphocron/issues>. Include a minimal
  reproducer (a failing test, a code excerpt).
- **Security issue** → see [SECURITY.md](SECURITY.md). Please don't open a
  public issue for vulnerabilities; the policy describes the disclosure path.
- **Design feedback or threat-model questions** → GitHub Discussions on the
  `skydeval/kryphocron` repo.

The companion lexicon JSON lives in
[`kryphocron-lexicons`](https://github.com/skydeval/kryphocron-lexicons);
lexicon-vocabulary suggestions belong there.

## License

**MPL-2.0** (Mozilla Public License 2.0). See `LICENSE`.

The MPL is file-level copyleft: modifications to MPL-2.0-licensed source files
must be released under MPL-2.0; downstream crates linking to `kryphocron` are
unconstrained and may ship under permissive licenses (MIT OR Apache-2.0
recommended for operator substrate components like PDS, AppView, etc.).

The companion `kryphocron-lexicons` crate ships its lexicon JSON under CC0-1.0
(public domain dedication); the wire vocabulary is universal and unencumbered.

## Related

- `kryphocron-lexicons` — companion crate shipping the lexicon JSON + Rust
  codegen wrappers. Required for consumers using lexicon-validated record types.

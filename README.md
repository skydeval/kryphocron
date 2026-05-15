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

```rust
use kryphocron::{
    AuditSinks, NoEncryption, OracleSet, TraceId,
    verification::verify_jwt,
};

// At substrate startup, install audit sinks, oracles, the DID
// resolver, and (optionally) an encryption resolver set:
let resolver_set = NoEncryption;  // v1 default; no encryption.

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

// Bind capability proofs against ctx; the audit pipeline fires
// terminal events on every bind, structurally.
```

The substrate's value isn't in the API ergonomics — it's in the
threat-model invariants the type system enforces.

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

**v0.1.0** ships the type architecture, lexicon strategy (via
the companion `kryphocron-lexicons` crate), audit event
vocabulary, inter-service auth (JWT verification, capability
claims, trust declarations + DID resolver, sync handshake
protocol, delegation receipts + chain rehydration), and
encryption hook surfaces.

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

# Security Policy

## Reporting a vulnerability

If you believe you've found a security issue in `kryphocron`,
please **do not** open a public GitHub issue. The substrate's
authority discipline is designed to be reviewed adversarially —
but disclosure works best for everyone when the maintainer
sees the report before the public does.

Report privately via:

- **GitHub private vulnerability reports** —
  <https://github.com/skydeval/kryphocron/security/advisories/new>.
  This is the preferred path. Reports are visible only to the
  repository's maintainers and to anyone you explicitly add as a
  collaborator on the advisory.

Please include:

1. A description of the issue and the impact you observed.
2. Reproduction steps or a minimal reproducing example.
3. The kryphocron version(s) affected.
4. Any suggested mitigation if you have one in mind.

If the issue involves cryptographic correctness, audit-pipeline
integrity, or any sealed-trait / `unsafe`-discipline assumption,
please mention that explicitly — those touch on commitments the
substrate makes in its threat model and warrant priority handling.

## Response timeline

The maintainer is a solo author; the following are best-effort
commitments calibrated to what's sustainable, not 24/7 oncall:

- **Acknowledgement of receipt**: within 5 business days.
- **Initial assessment** (severity + scope): within 14 days.
- **Coordinated disclosure window**: 90 days from initial
  acknowledgement, by default. Earlier disclosure is possible by
  mutual agreement when a fix is ready and deployed; later
  disclosure is possible by mutual agreement when the fix is
  non-trivial.

If the issue affects a downstream consumer (an operator running
kryphocron in their substrate), the maintainer will work with you
on coordinated disclosure that gives downstream operators time to
upgrade before the issue becomes public.

## Scope

The following are in scope for security reports:

- **Capability-proof forgeability.** Any path that produces a
  `UserProof`, `ChannelProof`, `SubstrateProof`, or
  `ModerationProof` outside the `authority::issue_*` chokepoints
  in safe Rust.
- **Audit-pipeline failure modes.** Any path where a committed
  bind produces no terminal audit event, or where a denied bind
  produces an event that misrepresents the outcome.
- **Tier-classification bypass.** Any path that lets a
  private-tier value reach a public-surface emission point by
  type, or that lets `tier::visible_to` return `Visible` for a
  combination the substrate commits to `Forbidden`.
- **Encoding-at-default bypass.** Any path that produces a
  private-tier record via the substrate's at-rest write seam
  (`encode_record_content`) without the installed `ContentCodec`
  running — i.e., any reachable code path that emits plaintext
  content where the substrate's type system promises encoding.
- **JWT / capability-claim signature handling.** Any path that
  accepts a malformed, expired, replayed, or
  improperly-algorithm-tagged JWT or claim.
- **Sync-handshake protocol violations.** Any path that admits a
  session whose handshake did not produce a verified
  `VerifiedSyncEstablished`.
- **Inter-service-auth nonce handling.** Replay-window
  violations, partition-cap bypass, etc.
- **`ContentCodec` contract violations.** Encoding succeeds but
  produces output the decoder rejects, codec stamp mismatches
  between encode and decode, rotation-mark generation collisions
  that admit cross-batch correlation, or any path that produces
  an `EncodedRecord` whose metadata misrepresents the codec or
  generation under which the content was produced.
- **`AuditEncryptionResolver` contract violations.** Any path
  that reaches a sensitive-representation decision with an
  inconsistent encryption context.

The following are **out of scope**:

- **Operator-policy decisions.** kryphocron defers many decisions
  to operator code (encryption algorithms, oracle backends, key
  storage). Bugs in operator implementations of those traits are
  out of scope for kryphocron; report them to the relevant
  operator project.
- **Timing-channel observability.** The substrate ships coarse
  timing equalization as a first defense, explicitly **not** a
  constant-time discipline. Reports of "I measured timing
  differences and could infer X" against the current timing
  surface are expected; the README documents this disclosure.
  Reports of timing channels that bypass the coarse-equalization
  commitments (e.g., the equalization stage doesn't fire) are in
  scope.
- **Laquna confidentiality.** The default `ContentCodec` (laquna)
  is a friction-encoding primitive, not confidentiality-grade
  encryption. Reports of the form "I decoded a laquna-encoded
  record using the published decoder and the public seed" are
  expected, not vulnerabilities — laquna's threat model is
  documented explicitly in the README's Privacy posture section,
  and the substrate's identity is friction at rest, not
  confidentiality at rest. Reports of `ContentCodec` integrity
  failures (covered above under in-scope) are different and are
  in scope.
- **Bugs in dependencies.** Report `ed25519-dalek`, `blake3`,
  `ciborium`, `serde_json`, `tokio`, `getrandom`, `chacha20`,
  `hkdf`, `sha2`, `zstd`, etc. issues upstream. If a dependency
  vulnerability affects kryphocron in a non-obvious way (e.g.,
  we're using an API in a way that exposes a known issue),
  please flag the kryphocron-specific exposure separately.
- **`tools.kryphocron.*` lexicon schema design.** The lexicons
  are CC0-licensed; suggestions and corrections are welcome via
  public GitHub issues on the `kryphocron-lexicons` repo (this is
  vocabulary design, not security).

## Disclosure history

Past advisories will be listed here once the project receives
any. None to date.

Advisories will also be posted to the repository's GitHub
security tab:
<https://github.com/skydeval/kryphocron/security/advisories>.

## Acknowledgements

Thank you for taking the time to report security issues
responsibly. If you'd like to be credited in disclosure
materials, please mention so in your report; the default is
public credit unless you request otherwise.
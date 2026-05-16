// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §7.2 / §7.5 verification submodule.
//!
//! Phase 4a wires §7.2 — the JWT verification chain — through
//! [`crate::verification::verify_jwt`]. Phase 4b wires §7.6 —
//! the capability-claim verification chain — through
//! [`crate::verification::verify_capability_claim`]. Phase 1
//! shipped the [`crate::verification::VerifiedJwt`] type with
//! private fields and a crate-internal constructor; Phase 4a
//! wired the constructor body. Phase 4b ships the parallel
//! [`crate::verification::VerifiedCapabilityClaim`] type and
//! constructor.
//!
//! [`crate::verification::VerifiedSyncMessage`] (§7.5) carries
//! a verified post-handshake sync-channel message; the
//! three-message handshake establishment evidence ships as
//! [`crate::verification::VerifiedSyncHello`],
//! [`crate::verification::VerifiedSyncAccept`], and
//! [`crate::verification::VerifiedSyncEstablished`] (Phase 4d).
//!
//! See §7.2 for the JWT verification flow, §7.5 for the
//! sync-handshake protocol.

use core::marker::PhantomData;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use smallvec::SmallVec;
use thiserror::Error;

use crate::authority::capability::CapabilityKind;
use crate::identity::{
    KeyId, PublicKey, ServiceIdentity, SessionId, SignatureAlgorithm, TraceId,
};
use crate::proto::Did;
use crate::resolver::{DidResolutionError, DidResolver};
use crate::sealed;
use crate::audit::BatchRejectionReason;
use crate::authority::capability::CapabilitySet;
use crate::authority::predicate::BindError;
use crate::wire::{
    accept_to_wire_bytes, decode_accept_wire, decode_established_wire,
    decode_hello_wire, decode_reject_wire, decode_wire_envelope,
    established_to_wire_bytes, hello_to_wire_bytes, reject_to_wire_bytes,
    verify_delegation_receipt, wire_envelope_is_canonical, AttributionChainWire,
    AttributionEntryWire, AttributionPrincipal, CapabilityClaim,
    DelegationReceiptPayload, HandshakeNonceTracker, JwtNonce, NonceFreshness,
    NonceIssuerKey, NoncePrincipal, NonceTracker, NonceTrackerError,
    ReceiptVerificationFailure, ResourceScope, SessionNonce, SyncChannelAccept,
    SyncChannelEstablished, SyncChannelHello, SyncChannelReject,
    SyncRequestedScope, CLAIM_DOMAIN_TAG, MAX_CAPABILITY_CLAIM_SIZE,
    MAX_HANDSHAKE_MESSAGE_SIZE,
};
use kryphocron_lexicons::SemVer;

/// JWT that passed signature **and** claim verification (§7.2).
///
/// Constructible only via [`verify_jwt`]; consumers receiving a
/// [`VerifiedJwt`] need not re-verify or trust the caller.
///
/// Outside-crate code cannot construct a [`VerifiedJwt`] via
/// struct-literal syntax — every field is private, including the
/// crate-sealed `_private: PhantomData<sealed::Token>` marker.
/// The compile-fail doctest below is the witness:
///
/// ```compile_fail
/// // Outside-crate construction must not work — the only way to
/// // obtain a `VerifiedJwt` is `verify_jwt`'s success path.
/// use kryphocron::verification::VerifiedJwt;
/// let _v = VerifiedJwt {
///     // fields are private; this fails E0451 / E0451-flavored.
/// };
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedJwt {
    issuer: Did,
    audience: ServiceIdentity,
    issued_at: SystemTime,
    expires_at: SystemTime,
    scope: JwtScope,
    nonce: Option<JwtNonce>,
    algorithm: SignatureAlgorithm,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedJwt {
    /// Crate-internal constructor. Reserved for [`verify_jwt`]
    /// after every §7.2 verification stage has succeeded; not
    /// reachable from outside `crate::verification`.
    #[must_use]
    pub(crate) fn new_internal(
        issuer: Did,
        audience: ServiceIdentity,
        issued_at: SystemTime,
        expires_at: SystemTime,
        scope: JwtScope,
        nonce: Option<JwtNonce>,
        algorithm: SignatureAlgorithm,
    ) -> Self {
        VerifiedJwt {
            issuer,
            audience,
            issued_at,
            expires_at,
            scope,
            nonce,
            algorithm,
            _private: PhantomData,
        }
    }

    /// Borrow the issuer DID.
    #[must_use]
    pub fn issuer(&self) -> &Did {
        &self.issuer
    }

    /// Borrow the audience service identity.
    #[must_use]
    pub fn audience(&self) -> &ServiceIdentity {
        &self.audience
    }

    /// `SystemTime` the JWT was issued.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// `SystemTime` the JWT expires.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Borrow the JWT scope (§7.2).
    #[must_use]
    pub fn scope(&self) -> &JwtScope {
        &self.scope
    }

    /// Borrow the optional nonce.
    #[must_use]
    pub fn nonce(&self) -> Option<&JwtNonce> {
        self.nonce.as_ref()
    }

    /// Return the verification algorithm.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// JWT verification configuration (§7.2).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JwtVerificationConfig {
    /// Maximum clock skew tolerated between issuer and verifier.
    /// Recommended: 30 seconds.
    pub max_clock_skew: Duration,
    /// Maximum permitted validity window. Recommended: 1 hour.
    pub max_validity_window: Duration,
    /// If `true`, JWTs without a nonce fail. Recommended: `false`
    /// for stateless reads, `true` for state-changing operations.
    pub require_nonce: bool,
    /// Algorithm allowlist. Recommended default:
    /// `&[SignatureAlgorithm::Ed25519]`.
    pub accepted_algorithms: &'static [SignatureAlgorithm],
}

impl Default for JwtVerificationConfig {
    fn default() -> Self {
        JwtVerificationConfig {
            max_clock_skew: Duration::from_secs(30),
            max_validity_window: Duration::from_secs(3600),
            require_nonce: false,
            accepted_algorithms: &[SignatureAlgorithm::Ed25519],
        }
    }
}

/// JWT scope vector (§7.2).
///
/// Operator-defined scope strings (typically NSID-shaped:
/// `com.atproto.repo.createRecord`). The substrate validates that
/// the requested operation falls within the scope at **capability
/// issuance time** (§4.3), not at ingress.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JwtScope {
    /// Scope strings.
    pub scopes: SmallVec<[String; 4]>,
}

/// JWT verification failure (§7.2).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtVerificationError {
    /// Token was structurally malformed.
    #[error("JWT malformed")]
    Malformed,
    /// Algorithm not in the allowlist.
    #[error("JWT algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// Signature did not verify.
    #[error("JWT signature invalid")]
    SignatureInvalid,
    /// JWT was expired.
    #[error("JWT expired (exp={exp:?}, now={now:?})")]
    Expired {
        /// `exp` claim from the JWT.
        exp: SystemTime,
        /// Current time at verification.
        now: SystemTime,
    },
    /// JWT is not yet valid.
    #[error("JWT not yet valid")]
    NotYetValid {
        /// `nbf` claim from the JWT.
        nbf: SystemTime,
        /// Current time at verification.
        now: SystemTime,
        /// Clock skew tolerated.
        skew: Duration,
    },
    /// Audience mismatch.
    #[error("JWT wrong audience")]
    WrongAudience {
        /// Expected (local) audience.
        expected: ServiceIdentity,
        /// Audience claimed by JWT.
        got: ServiceIdentity,
    },
    /// Issuer DID failed to resolve.
    #[error("JWT issuer resolution failed: {0}")]
    IssuerResolutionFailed(DidResolutionError),
    /// Issuer's signing key not in DID document.
    #[error("issuer key not in DID document")]
    IssuerKeyNotInDocument,
    /// Validity window too long.
    #[error("validity window too long")]
    ValidityWindowTooLong {
        /// Requested validity window.
        window: Duration,
        /// Maximum permitted.
        max: Duration,
    },
    /// Nonce required but missing.
    #[error("nonce missing")]
    NonceMissing,
    /// Nonce was a replay.
    #[error("nonce replay")]
    NonceReplay,
}

/// Verify a raw JWT against the configured DID resolver (§7.2).
///
/// `raw` may be either the bare JWT (`header.payload.signature`)
/// or a full HTTP `Authorization` header value (`Bearer <jwt>`);
/// the function strips the `Bearer ` prefix when present.
///
/// The verification chain runs all five §7.2 stages in order:
///
/// 1. Authorization-header parsing + JWT structural parse.
/// 2. Algorithm allowlist check (default: `[Ed25519]`).
/// 3. Issuer DID resolution to obtain the signing key.
/// 4. Signature verification.
/// 5. Claims verification (iss / aud / exp / iat / nbf / nonce /
///    validity-window / scope extraction).
///
/// On success returns [`VerifiedJwt`] — an unforgeable token; the
/// crate's `ingress` paths accept it as evidence that JWT
/// verification ran without trusting the caller.
///
/// Replay protection (the [`crate::wire::NonceTracker`] check) is
/// **not** wired in Phase 4a; nonce extraction succeeds, replay
/// rejection is opt-in via a separately-supplied tracker (Phase 4b
/// integration point).
///
/// Audit-emit is the caller's responsibility — the `authority`
/// module emits
/// [`crate::audit::UserAuditEvent::CapabilityIssuanceDenied`] at
/// the ingress chokepoint with
/// [`crate::authority::DenialReason::JwtVerificationFailed`]
/// carrying the returned error.
///
/// # Errors
///
/// Returns [`JwtVerificationError`] on any failure. Each variant
/// is reachable independently from the verification chain; see
/// the per-variant doc for the failure path.
pub async fn verify_jwt(
    raw: &str,
    local_audience: &ServiceIdentity,
    resolver: &dyn DidResolver,
    config: &JwtVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<VerifiedJwt, JwtVerificationError> {
    // 1. Strip `Bearer ` prefix if present and structurally parse
    //    the three base64url segments.
    let token = parse_authorization_header(raw)?;
    let parsed = ParsedJwt::parse(token)?;

    // 2. Allowlist enforcement. The `alg: "none"` case is rejected
    //    inside `ParsedJwt::parse` as `Malformed` so the allowlist
    //    branch is never reached for that attack class (§7.2's
    //    alg-confusion discipline: the `none` rejection is part of
    //    the parser, not the allowlist).
    if !config.accepted_algorithms.contains(&parsed.algorithm) {
        return Err(JwtVerificationError::UnsupportedAlgorithm(parsed.algorithm));
    }

    // 3. Resolve the issuer DID to obtain a signing key. The
    //    issuer DID comes from the JWT payload (`iss` claim). The
    //    JWT header's optional `kid` selects which verification
    //    method from the resolved DID document; absent `kid` means
    //    "any verification method is acceptable" — try them in
    //    document order.
    let issuer = parsed.payload_iss()?;
    let document = resolver
        .resolve(&issuer, deadline, trace_id)
        .await
        .map_err(JwtVerificationError::IssuerResolutionFailed)?;
    let public_key = select_signing_key(&document, parsed.kid_hint(), parsed.algorithm)?;

    // 4. Signature verification. Dispatch by algorithm.
    verify_signature(parsed.signing_input(), &parsed.signature, parsed.algorithm, &public_key)?;

    // 5. Claims verification. Constructs the `VerifiedJwt` on
    //    success.
    let now = SystemTime::now();
    parsed.verify_claims_and_construct(local_audience, config, issuer, now)
}

// ============================================================
// §7.2 — Authorization header + raw JWT parsing.
// ============================================================

/// Strip an optional `Bearer ` (case-insensitive scheme,
/// case-sensitive token) prefix per RFC 7235.
fn parse_authorization_header(raw: &str) -> Result<&str, JwtVerificationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(JwtVerificationError::Malformed);
    }
    if let Some(rest) = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .or_else(|| trimmed.strip_prefix("BEARER "))
    {
        let token = rest.trim_start();
        if token.is_empty() {
            return Err(JwtVerificationError::Malformed);
        }
        return Ok(token);
    }
    // No `Bearer ` prefix — treat the input as a bare JWT. This
    // accommodates callers that have already stripped the prefix
    // upstream.
    Ok(trimmed)
}

/// Decoded JWT segments + the original signing input (the
/// `<header>.<payload>` substring needed for signature
/// verification).
struct ParsedJwt<'a> {
    /// Parsed header JSON.
    header: serde_json::Value,
    /// Parsed payload JSON.
    payload: serde_json::Value,
    /// Decoded signature bytes.
    signature: Vec<u8>,
    /// `<header>.<payload>` substring (the signing input over
    /// which the signature is computed).
    signing_input_str: &'a str,
    /// Algorithm extracted from the header and validated against
    /// the JWT-spec algorithm name.
    algorithm: SignatureAlgorithm,
}

impl<'a> ParsedJwt<'a> {
    fn parse(token: &'a str) -> Result<Self, JwtVerificationError> {
        // A JWT has exactly two `.` separators. `splitn(3, '.')` to
        // tolerate a trailing-dot signature edge case is wrong —
        // RFC 7519 §3 commits exactly three segments separated by
        // exactly two dots.
        let mut iter = token.split('.');
        let header_b64 = iter.next().ok_or(JwtVerificationError::Malformed)?;
        let payload_b64 = iter.next().ok_or(JwtVerificationError::Malformed)?;
        let signature_b64 = iter.next().ok_or(JwtVerificationError::Malformed)?;
        if iter.next().is_some() {
            return Err(JwtVerificationError::Malformed);
        }
        if header_b64.is_empty() || payload_b64.is_empty() || signature_b64.is_empty() {
            return Err(JwtVerificationError::Malformed);
        }

        // The signing input is the concatenation of header_b64 and
        // payload_b64 with the dot retained between them (RFC 7515
        // §5.1). We need the original string, not a re-built one,
        // so signature input bytes match exactly what the issuer
        // signed.
        let signing_input_len = header_b64.len() + 1 + payload_b64.len();
        let signing_input_str = &token[..signing_input_len];

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| JwtVerificationError::Malformed)?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| JwtVerificationError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| JwtVerificationError::Malformed)?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| JwtVerificationError::Malformed)?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| JwtVerificationError::Malformed)?;

        let algorithm = parse_alg_header(&header)?;

        Ok(ParsedJwt {
            header,
            payload,
            signature,
            signing_input_str,
            algorithm,
        })
    }

    fn signing_input(&self) -> &[u8] {
        self.signing_input_str.as_bytes()
    }

    fn kid_hint(&self) -> Option<&str> {
        self.header.get("kid")?.as_str()
    }

    fn payload_iss(&self) -> Result<Did, JwtVerificationError> {
        let iss = self
            .payload
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .ok_or(JwtVerificationError::Malformed)?;
        Did::new(iss).map_err(|_| JwtVerificationError::Malformed)
    }

    fn verify_claims_and_construct(
        self,
        local_audience: &ServiceIdentity,
        config: &JwtVerificationConfig,
        issuer: Did,
        now: SystemTime,
    ) -> Result<VerifiedJwt, JwtVerificationError> {
        let p = &self.payload;

        // `aud`. JWT standard allows a string or array; ATProto
        // convention uses a single string DID. v1 accepts only the
        // string form — array support is a future-extension
        // for the broader-ATProto-compatibility roll-out.
        let aud_str = p
            .get("aud")
            .and_then(serde_json::Value::as_str)
            .ok_or(JwtVerificationError::Malformed)?;
        let aud_did = Did::new(aud_str).map_err(|_| JwtVerificationError::Malformed)?;
        if aud_did != *local_audience.service_did() {
            // Construct a placeholder `ServiceIdentity` for the
            // `got` field — the JWT `aud` claim is a DID string,
            // not a ServiceIdentity, so we synthesize one with
            // zero key material to fit the §7.2 error variant
            // shape. See note for the shape-vs-reality
            // mismatch.
            let got_placeholder = ServiceIdentity::new_internal(
                aud_did,
                KeyId::from_bytes([0u8; 32]),
                PublicKey {
                    algorithm: SignatureAlgorithm::Ed25519,
                    bytes: [0u8; 32],
                },
                None,
            );
            return Err(JwtVerificationError::WrongAudience {
                expected: local_audience.clone(),
                got: got_placeholder,
            });
        }

        // `iat` (required per §7.2 / kickoff §5).
        let iat_secs = p
            .get("iat")
            .and_then(serde_json::Value::as_u64)
            .ok_or(JwtVerificationError::Malformed)?;
        let iat = SystemTime::UNIX_EPOCH + Duration::from_secs(iat_secs);

        // `exp` (required).
        let exp_secs = p
            .get("exp")
            .and_then(serde_json::Value::as_u64)
            .ok_or(JwtVerificationError::Malformed)?;
        let exp = SystemTime::UNIX_EPOCH + Duration::from_secs(exp_secs);

        // `nbf` (optional).
        let nbf = p
            .get("nbf")
            .and_then(serde_json::Value::as_u64)
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s));

        // Validity window: exp − iat ≤ max_validity_window. The
        // check uses unsigned-saturating subtraction since `iat`
        // greater than `exp` is itself an error caught by the
        // expiry check below.
        let window = exp.duration_since(iat).unwrap_or(Duration::ZERO);
        if window > config.max_validity_window {
            return Err(JwtVerificationError::ValidityWindowTooLong {
                window,
                max: config.max_validity_window,
            });
        }

        // Expiry. `exp` must be in the future (or within
        // `max_clock_skew` of now). Equivalent: now ≤ exp + skew.
        if now > exp + config.max_clock_skew {
            return Err(JwtVerificationError::Expired { exp, now });
        }

        // `nbf`: if present, must be in the past (within skew).
        if let Some(nbf_t) = nbf {
            if now + config.max_clock_skew < nbf_t {
                return Err(JwtVerificationError::NotYetValid {
                    nbf: nbf_t,
                    now,
                    skew: config.max_clock_skew,
                });
            }
        }

        // `iat`: must be in the past (within skew). A future-dated
        // `iat` reuses the `NotYetValid` variant since it indicates
        // the same operator-debug condition (issuer's clock ahead
        // of verifier's).
        if now + config.max_clock_skew < iat {
            return Err(JwtVerificationError::NotYetValid {
                nbf: iat,
                now,
                skew: config.max_clock_skew,
            });
        }

        // Scope extraction. ATProto convention varies between
        // `scope` and `scp` field names and between space-delimited
        // string and JSON array values. Accept both names and both
        // formats per the kickoff guidance.
        let scope = parse_scope_field(p);

        // Nonce extraction. v1 expects the nonce as a base64url-
        // encoded 16-byte value. If `require_nonce` is true and
        // missing, fail. Replay rejection is opt-in via a separate
        // `NonceTracker` integration (Phase 4b).
        let nonce = parse_nonce_field(p, config.require_nonce)?;

        Ok(VerifiedJwt::new_internal(
            issuer,
            local_audience.clone(),
            iat,
            exp,
            scope,
            nonce,
            self.algorithm,
        ))
    }
}

/// Map a JWT `alg` header value to a [`SignatureAlgorithm`].
///
/// Returns [`JwtVerificationError::Malformed`] for missing /
/// non-string `alg` and for the literal `"none"` (per §7.2's
/// alg-confusion discipline: `none` rejection is a parser
/// concern, not an allowlist concern, so the audit channel sees
/// `Malformed` rather than the misleading
/// `UnsupportedAlgorithm(SignatureAlgorithm::Ed25519)`).
fn parse_alg_header(
    header: &serde_json::Value,
) -> Result<SignatureAlgorithm, JwtVerificationError> {
    let alg = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or(JwtVerificationError::Malformed)?;
    if alg.eq_ignore_ascii_case("none") {
        return Err(JwtVerificationError::Malformed);
    }
    match alg {
        "EdDSA" => Ok(SignatureAlgorithm::Ed25519),
        "ES256" => Ok(SignatureAlgorithm::Es256),
        "ES256K" => Ok(SignatureAlgorithm::Es256K),
        // Unknown algorithm names are treated as malformed: the
        // JWT header `alg` field is a registered IANA value space
        // and unknowns indicate either a misformatted JWT or an
        // attempted alg-confusion attack. Either way the audit
        // signal is "this token is not parseable" rather than
        // "this algorithm is not configured."
        _ => Err(JwtVerificationError::Malformed),
    }
}

// ============================================================
// §7.2 — Signing-key resolution and signature verification.
// ============================================================

/// Pick a [`PublicKey`] from a resolved DID document for
/// signature verification.
///
/// If the JWT header carried a `kid`, look for a verification
/// method whose [`KeyId`] matches the hint. Without `kid`, return
/// the first verification method whose algorithm matches the JWT.
/// Failing to find a match returns
/// [`JwtVerificationError::IssuerKeyNotInDocument`].
///
/// `kid` matching uses byte-equality on the lowercase hex
/// rendering of the [`KeyId`] (`KeyId` is 32 bytes; the JWT `kid`
/// is operator-supplied free text but ATProto convention uses the
/// hex rendering or a full DID-fragment URI). Phase 4a accepts
/// both: if the hint exactly matches the hex-rendered key id, or
/// the hint *ends with* the hex-rendered key id (the
/// `did:plc:...#<keyid>` URI shape), the match succeeds.
fn select_signing_key(
    document: &crate::resolver::DidDocument,
    kid_hint: Option<&str>,
    algorithm: SignatureAlgorithm,
) -> Result<PublicKey, JwtVerificationError> {
    let methods = &document.verification_methods;
    if methods.is_empty() {
        return Err(JwtVerificationError::IssuerKeyNotInDocument);
    }

    if let Some(hint) = kid_hint {
        // Try exact / suffix match first.
        for (kid, key) in methods {
            let kid_hex = kid_to_hex(kid);
            if hint == kid_hex || hint.ends_with(&kid_hex) {
                if key.algorithm == algorithm {
                    return Ok(*key);
                }
                return Err(JwtVerificationError::IssuerKeyNotInDocument);
            }
        }
        // Hint provided but didn't match anything.
        return Err(JwtVerificationError::IssuerKeyNotInDocument);
    }

    // No hint — first matching algorithm wins.
    for (_kid, key) in methods {
        if key.algorithm == algorithm {
            return Ok(*key);
        }
    }
    Err(JwtVerificationError::IssuerKeyNotInDocument)
}

fn kid_to_hex(kid: &KeyId) -> String {
    let mut s = String::with_capacity(64);
    for b in kid.as_bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify a JWT signature for the given algorithm.
///
/// Ed25519 is fully implemented in Phase 4a. ES256 / ES256K stub
/// with `UnsupportedAlgorithm` until a later sub-phase commits
/// the `p256` / `k256` crate dependencies; tracked alongside
/// work.
fn verify_signature(
    signing_input: &[u8],
    signature: &[u8],
    algorithm: SignatureAlgorithm,
    public_key: &PublicKey,
) -> Result<(), JwtVerificationError> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                return Err(JwtVerificationError::SignatureInvalid);
            }
            let mut sig_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
            sig_bytes.copy_from_slice(signature);
            let sig = Ed25519Signature::from_bytes(&sig_bytes);
            let key = VerifyingKey::from_bytes(&public_key.bytes)
                .map_err(|_| JwtVerificationError::SignatureInvalid)?;
            key.verify(signing_input, &sig)
                .map_err(|_| JwtVerificationError::SignatureInvalid)
        }
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es256K => {
            // Chainlinked: Phase 4a recognizes the variants but
            // does not ship the `p256` / `k256` crate dependencies
            // yet. Operators configuring these in
            // `accepted_algorithms` will see this error.
            Err(JwtVerificationError::UnsupportedAlgorithm(algorithm))
        }
    }
}

// ============================================================
// §7.2 — Scope and nonce extraction.
// ============================================================

/// Parse the JWT scope claim. Accepts either `scope` or `scp` as
/// the field name and either a space-delimited string or a JSON
/// array of strings as the value. Missing or unrecognized shapes
/// yield an empty [`JwtScope`] — which §7.2's empty-is-fail-closed
/// rule treats as authorizing no operations.
fn parse_scope_field(payload: &serde_json::Value) -> JwtScope {
    let raw = payload.get("scope").or_else(|| payload.get("scp"));
    let mut scopes: SmallVec<[String; 4]> = SmallVec::new();
    if let Some(value) = raw {
        if let Some(s) = value.as_str() {
            for token in s.split_ascii_whitespace() {
                if !token.is_empty() {
                    scopes.push(token.to_string());
                }
            }
        } else if let Some(arr) = value.as_array() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !s.is_empty() {
                        scopes.push(s.to_string());
                    }
                }
            }
        }
    }
    JwtScope { scopes }
}

/// Parse the optional JWT nonce claim. v1 accepts a base64url-
/// encoded 16-byte value. Missing nonce with `require_nonce: true`
/// fails with [`JwtVerificationError::NonceMissing`]; missing with
/// `require_nonce: false` returns `Ok(None)`.
///
/// Replay rejection is opt-in via a separately-supplied
/// [`crate::wire::NonceTracker`] (Phase 4b integration point);
/// Phase 4a only extracts the nonce.
fn parse_nonce_field(
    payload: &serde_json::Value,
    require_nonce: bool,
) -> Result<Option<JwtNonce>, JwtVerificationError> {
    let nonce_str = payload.get("nonce").and_then(serde_json::Value::as_str);
    match (nonce_str, require_nonce) {
        (None, true) => Err(JwtVerificationError::NonceMissing),
        (None, false) => Ok(None),
        (Some(s), _) => {
            let bytes = URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|_| JwtVerificationError::Malformed)?;
            if bytes.len() != 16 {
                return Err(JwtVerificationError::Malformed);
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            Ok(Some(JwtNonce::from_bytes(arr)))
        }
    }
}

// ============================================================
// §7.6 capability-claim verification.
// ============================================================

/// Capability claim that has passed wire-canonicality, signature,
/// and claim verification (§7.6).
///
/// Constructible only via [`verify_capability_claim`]; consumers
/// receiving a [`VerifiedCapabilityClaim`] need not re-verify or
/// trust the caller.
///
/// Outside-crate code cannot construct via struct-literal syntax
/// — every field is private, including the crate-sealed
/// `_private: PhantomData<sealed::Token>` marker.
///
/// ```compile_fail
/// // Outside-crate construction must not work.
/// use kryphocron::verification::VerifiedCapabilityClaim;
/// let _v = VerifiedCapabilityClaim {
///     // fields private; this fails to compile.
/// };
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedCapabilityClaim {
    issuer: ServiceIdentity,
    subject: Did,
    capabilities: Vec<CapabilityKind>,
    resource_scope: ResourceScope,
    trace_id: TraceId,
    issued_at: SystemTime,
    expires_at: SystemTime,
    /// Verified upstream attribution chain (Phase 4e). `None` for
    /// [`crate::wire::ClaimOrigin::SelfOriginated`]; `Some(chain)`
    /// for `DelegatedFromUpstream`. The chain has been
    /// signature- and monotonicity-verified by
    /// [`verify_attribution_chain`].
    chain: Option<crate::AttributionChain>,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedCapabilityClaim {
    /// Crate-internal constructor. Reserved for
    /// [`verify_capability_claim`] after every §7.6 verification
    /// stage has succeeded; not reachable from outside
    /// `crate::verification`.
    #[must_use]
    pub(crate) fn new_internal(
        issuer: ServiceIdentity,
        subject: Did,
        capabilities: Vec<CapabilityKind>,
        resource_scope: ResourceScope,
        trace_id: TraceId,
        issued_at: SystemTime,
        expires_at: SystemTime,
        chain: Option<crate::AttributionChain>,
    ) -> Self {
        VerifiedCapabilityClaim {
            issuer,
            subject,
            capabilities,
            resource_scope,
            trace_id,
            issued_at,
            expires_at,
            chain,
            _private: PhantomData,
        }
    }

    /// Borrow the issuer service identity.
    #[must_use]
    pub fn issuer(&self) -> &ServiceIdentity {
        &self.issuer
    }
    /// Borrow the subject DID.
    #[must_use]
    pub fn subject(&self) -> &Did {
        &self.subject
    }
    /// Borrow the requested capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityKind] {
        &self.capabilities
    }
    /// Borrow the resource scope.
    #[must_use]
    pub fn resource_scope(&self) -> &ResourceScope {
        &self.resource_scope
    }
    /// Forensic trace id.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }
    /// Issued-at instant.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }
    /// Expires-at instant.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    /// Borrow the verified upstream attribution chain. Phase 4e:
    /// returns `None` for `SelfOriginated` claims; `Some(chain)`
    /// for `DelegatedFromUpstream` claims whose chain passed
    /// [`verify_attribution_chain`].
    #[must_use]
    pub fn chain(&self) -> Option<&crate::AttributionChain> {
        self.chain.as_ref()
    }
}

/// Sync-channel message that has passed handshake-aware
/// verification (§7.5 + §7.6).
///
/// Phase 4b ships the type *shape*; the actual verification path
/// requires the sync handshake which lands in Phase 4d. The
/// crate-internal constructor remains unreachable until 4d
/// connects the handshake-evidence wiring.
#[derive(Debug, Clone)]
pub struct VerifiedSyncMessage {
    session_identity: ServiceIdentity,
    session_id: SessionId,
    payload: VerifiedCapabilityClaim,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedSyncMessage {
    /// Borrow the session-bound peer identity.
    #[must_use]
    pub fn session_identity(&self) -> &ServiceIdentity {
        &self.session_identity
    }
    /// Return the session id from the originating handshake.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    /// Borrow the inner verified capability claim.
    #[must_use]
    pub fn payload(&self) -> &VerifiedCapabilityClaim {
        &self.payload
    }
}

/// Capability-claim verification configuration (§7.6).
///
/// Parallel to [`JwtVerificationConfig`]; sets the same defaults
/// where the two contexts share semantics
/// (`max_clock_skew = 30s`, `accepted_algorithms = [Ed25519]`)
/// plus a 600s `max_validity_window` matching
/// [`crate::MAX_CLAIM_VALIDITY`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClaimVerificationConfig {
    /// Maximum clock skew tolerated between issuer and verifier.
    pub max_clock_skew: Duration,
    /// Maximum permitted validity window (≤ 600s per §4.8).
    pub max_validity_window: Duration,
    /// Algorithm allowlist; default `[Ed25519]` per §7.2.
    pub accepted_algorithms: &'static [SignatureAlgorithm],
}

impl Default for ClaimVerificationConfig {
    fn default() -> Self {
        ClaimVerificationConfig {
            max_clock_skew: Duration::from_secs(30),
            max_validity_window: Duration::from_secs(600),
            accepted_algorithms: &[SignatureAlgorithm::Ed25519],
        }
    }
}

/// Capability-claim verification failure (§7.6).
///
/// Parallel structure to [`JwtVerificationError`]; the two enums
/// are intentionally separate because the failure modes differ
/// (CBOR canonicality, capability-class wire-eligibility,
/// nonce-tracker backend errors).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ClaimVerificationError {
    /// Wire envelope is structurally malformed: bad scheme prefix,
    /// base64url decode failure, CBOR decode failure, non-canonical
    /// CBOR encoding (the §7 round-4 hazard), missing field, type
    /// mismatch, or unrecognized capability/algorithm name.
    #[error("claim malformed")]
    Malformed,
    /// Algorithm not in the allowlist.
    #[error("claim algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// Signature did not verify against the issuer's signing key.
    #[error("claim signature invalid")]
    SignatureInvalid,
    /// Claim has expired.
    #[error("claim expired (exp={exp:?}, now={now:?})")]
    Expired {
        /// `expires_at` from the claim.
        exp: SystemTime,
        /// Current time at verification.
        now: SystemTime,
    },
    /// Claim is not yet valid (`issued_at` in the future beyond
    /// skew tolerance).
    #[error("claim not yet valid")]
    NotYetValid {
        /// `issued_at` from the claim.
        iat: SystemTime,
        /// Current time at verification.
        now: SystemTime,
        /// Clock skew tolerated.
        skew: Duration,
    },
    /// Audience mismatch. Per Phase 4a note, the `got`
    /// field carries the claimed-audience DID directly (no
    /// synthetic `ServiceIdentity` placeholder).
    #[error("claim wrong audience")]
    WrongAudience {
        /// Expected (local) audience.
        expected: ServiceIdentity,
        /// Audience claimed by the wire envelope.
        got: Did,
    },
    /// Issuer DID failed to resolve.
    #[error("claim issuer resolution failed: {0}")]
    IssuerResolutionFailed(DidResolutionError),
    /// Issuer's signing key not in DID document or rotation
    /// history.
    #[error("issuer key not in DID document")]
    IssuerKeyNotInDocument,
    /// `expires_at - issued_at` exceeds the configured maximum.
    #[error("validity window too long")]
    ValidityWindowTooLong {
        /// Requested validity window.
        window: Duration,
        /// Maximum permitted.
        max: Duration,
    },
    /// Wire envelope exceeds [`MAX_CAPABILITY_CLAIM_SIZE`].
    #[error("claim size {size} exceeds max {max}")]
    ClaimTooLarge {
        /// Wire envelope size.
        size: usize,
        /// Maximum permitted.
        max: usize,
    },
    /// Nonce previously observed under the same issuer partition
    /// within the tracker's retention window.
    #[error("claim nonce replay")]
    NonceReplay,
    /// Nonce tracker backend failure.
    #[error("nonce tracker failure: {0}")]
    NonceTrackerFailed(NonceTrackerError),
    /// §4.8 W6 violation observed at receive time: claim
    /// references a substrate-class or moderation-class
    /// capability that should never appear on the wire. The
    /// substrate's own claims fail at construction, but external
    /// claims must be re-checked because they may have been
    /// minted by a non-substrate or malicious party.
    #[error("non-wire-eligible capability {0:?} on the wire")]
    NonWireEligibleCapability(CapabilityKind),
    /// §4.8 W9 / W10 violation observed at receive time: claim's
    /// scope is not permitted for one of its declared
    /// capabilities. Belt-and-suspenders to construction-time
    /// checks.
    #[error("scope variant not permitted for class")]
    NonexhaustiveScopeForClass,
    /// §4.8 W11 / W12 / W13 (Phase 4e): claim is
    /// `DelegatedFromUpstream` but the wire chain failed
    /// receipt-verification. Carries the per-hop failure detail
    /// produced by [`verify_attribution_chain`].
    #[error("attribution chain invalid")]
    AttributionChainInvalid(BindError),
    /// §4.8 W13 (Phase 4e): claim's `capabilities` exceeds the
    /// last chain hop's `granted_capabilities`. The chain itself
    /// passed receipt verification (every hop's signature valid
    /// and inter-hop monotonicity held); the final claim attempted
    /// to grant beyond what the last hop's principal was
    /// authorized for.
    #[error("claim capabilities exceed last chain hop's granted set")]
    ClaimExceedsChainTail,
}

/// Verify a capability-claim wire envelope against the configured
/// DID resolver and nonce tracker (§7.6).
///
/// `raw_header` may be either the bare base64url-encoded wire
/// envelope or a full HTTP `Authorization` header value
/// (`KryphocronClaim <base64url>`); the function strips the scheme
/// prefix when present.
///
/// The verification chain runs all §7.6 receive-time enforcement
/// stages in order:
///
/// 1. Authorization-header scheme + base64url decode.
/// 2. Wire-bytes size ceiling ([`MAX_CAPABILITY_CLAIM_SIZE`]).
/// 3. Round-trip canonicality (re-encoded bytes byte-equal input;
///    closes the §7 round-4 hazard).
/// 4. CBOR structural decode into payload + signature.
/// 5. Algorithm allowlist check.
/// 6. Audience equality against `local_audience.service_did()`.
/// 7. W6 / W9 / W10 belt-and-suspenders against externally-minted
///    claims (substrate's own claims fail at construction).
/// 8. Validity window ≤ `config.max_validity_window`.
/// 9. `expires_at` future (within skew); `issued_at` past (within
///    skew).
/// 10. Issuer DID resolution + signing-key selection.
/// 11. Domain-separated Ed25519 signature verification over the
///     re-encoded canonical payload.
/// 12. Nonce-tracker check-and-record under the
///     `(NonceKind::CapabilityClaim, NonceIssuerKey)` partition.
/// 13. Construct [`VerifiedCapabilityClaim`] via the
///     crate-internal constructor.
///
/// On success returns [`VerifiedCapabilityClaim`] — an unforgeable
/// token that ingress paths accept as evidence that §7.6
/// verification ran without trusting the caller.
///
/// `ClaimOrigin::DelegatedFromUpstream` payloads are rejected as
/// `Malformed` in Phase 4b: receipt-chain verification (W11/W12/W13)
/// lands in Phase 4e. SelfOriginated claims succeed.
///
/// # Errors
///
/// Returns [`ClaimVerificationError`] on any failure.
pub async fn verify_capability_claim(
    raw_header: &str,
    local_audience: &ServiceIdentity,
    resolver: &dyn DidResolver,
    nonce_tracker: &dyn NonceTracker,
    config: &ClaimVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
    origin_authorized_capabilities: &CapabilitySet,
) -> Result<VerifiedCapabilityClaim, ClaimVerificationError> {
    // 1. Strip `KryphocronClaim ` prefix (case-insensitive scheme)
    //    and base64url-decode.
    let token = parse_claim_header(raw_header)?;
    let wire_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ClaimVerificationError::Malformed)?;

    // 2. Wire-bytes size ceiling.
    if wire_bytes.len() > MAX_CAPABILITY_CLAIM_SIZE {
        return Err(ClaimVerificationError::ClaimTooLarge {
            size: wire_bytes.len(),
            max: MAX_CAPABILITY_CLAIM_SIZE,
        });
    }

    // 3. Round-trip canonicality. Reject non-canonical encodings
    //    as Malformed — closes the §7 round-4 hazard at the
    //    boundary.
    if !wire_envelope_is_canonical(&wire_bytes) {
        return Err(ClaimVerificationError::Malformed);
    }

    // 4. Decode the wire envelope.
    let (
        issuer,
        audience,
        subject,
        origin,
        capabilities,
        resource_scope,
        nonce,
        trace_id_field,
        issued_at,
        expires_at,
        signature,
    ) = decode_wire_envelope(&wire_bytes).map_err(|()| ClaimVerificationError::Malformed)?;

    // 5. Algorithm allowlist.
    if !config.accepted_algorithms.contains(&signature.algorithm) {
        return Err(ClaimVerificationError::UnsupportedAlgorithm(signature.algorithm));
    }

    // 6. Audience equality. Per Phase 4a note, the `got`
    //    field carries the claimed DID directly (not a synthetic
    //    placeholder ServiceIdentity).
    if audience.service_did() != local_audience.service_did() {
        return Err(ClaimVerificationError::WrongAudience {
            expected: local_audience.clone(),
            got: audience.service_did().clone(),
        });
    }

    // 7. W6 / W9 / W10 belt-and-suspenders. The substrate's own
    //    claims pass these checks at construction; external claims
    //    must be re-checked.
    for cap in &capabilities {
        if !cap.is_wire_eligible() {
            return Err(ClaimVerificationError::NonWireEligibleCapability(*cap));
        }
        if !class_permits_scope(cap.class(), &resource_scope) {
            return Err(ClaimVerificationError::NonexhaustiveScopeForClass);
        }
    }

    // 8. Validity window.
    let window = expires_at
        .duration_since(issued_at)
        .unwrap_or(Duration::ZERO);
    if window > config.max_validity_window {
        return Err(ClaimVerificationError::ValidityWindowTooLong {
            window,
            max: config.max_validity_window,
        });
    }

    // 9. Expiry / not-yet-valid (clock-skew tolerant).
    let now = SystemTime::now();
    if now > expires_at + config.max_clock_skew {
        return Err(ClaimVerificationError::Expired {
            exp: expires_at,
            now,
        });
    }
    if now + config.max_clock_skew < issued_at {
        return Err(ClaimVerificationError::NotYetValid {
            iat: issued_at,
            now,
            skew: config.max_clock_skew,
        });
    }

    // 10. Issuer DID resolution + signing-key selection. The
    //     verifier's request `trace_id` (not the claim's
    //     `trace_id_field`) is what attributes any rotation /
    //     invalidation audit emitted as a side-effect of this
    //     resolution: rotations detected during this verification
    //     are events of the verifier's request, not of the original
    //     issuer-side context.
    let document = resolver
        .resolve(issuer.service_did(), deadline, trace_id)
        .await
        .map_err(ClaimVerificationError::IssuerResolutionFailed)?;
    let public_key = select_signing_key_for_claim(
        &document,
        issuer.key_id(),
        signature.algorithm,
    )?;

    // 11. Re-encode the canonical payload (no signature field) and
    //     verify the signature with domain separation.
    //     Note: `decode_claim_origin` rejects DelegatedFromUpstream
    //     in Phase 4b. SelfOriginated payloads round-trip here.
    let received_claim = CapabilityClaim::new_internal_received(
        issuer.clone(),
        audience,
        subject.clone(),
        origin,
        capabilities.clone(),
        resource_scope.clone(),
        nonce,
        trace_id_field,
        issued_at,
        expires_at,
        signature,
    );
    let canonical_payload = received_claim.canonical_payload_bytes();
    let mut signing_input =
        Vec::with_capacity(CLAIM_DOMAIN_TAG.len() + canonical_payload.len());
    signing_input.extend_from_slice(CLAIM_DOMAIN_TAG);
    signing_input.extend_from_slice(&canonical_payload);
    verify_claim_signature(
        &signing_input,
        &received_claim.signature().bytes,
        signature.algorithm,
        &public_key,
    )?;

    // 12. Nonce-tracker check-and-record.
    let issuer_partition = NonceIssuerKey {
        principal: NoncePrincipal::Service(issuer.service_did().clone()),
        key_id: issuer.key_id(),
    };
    let nonce_bytes = *received_claim.nonce().as_bytes();
    match nonce_tracker
        .record(
            crate::wire::NonceKind::CapabilityClaim,
            &issuer_partition,
            &nonce_bytes,
            now,
        )
        .map_err(ClaimVerificationError::NonceTrackerFailed)?
    {
        NonceFreshness::Fresh => {}
        NonceFreshness::Replay { .. } => return Err(ClaimVerificationError::NonceReplay),
    }

    // 14. §4.8 W11 / W12 / W13 chain verification (Phase 4e).
    //     If the claim is DelegatedFromUpstream, walk the chain
    //     under origin_authorized_capabilities. The verifier's
    //     request `trace_id` (not the claim's `trace_id_field`)
    //     attributes resolution-side audit emits during the walk.
    let verified_chain = match received_claim.origin() {
        crate::wire::ClaimOrigin::SelfOriginated => None,
        crate::wire::ClaimOrigin::DelegatedFromUpstream { chain } => {
            let chain_clone = chain.clone();
            let verified = verify_attribution_chain(
                &chain_clone,
                origin_authorized_capabilities,
                resolver,
                deadline,
                trace_id,
            )
            .await
            .map_err(ClaimVerificationError::AttributionChainInvalid)?;
            // §4.8 W13 final-hop monotonicity: claim.capabilities
            // ⊆ entries.last().granted_capabilities. The chain
            // walker already verified hop[0..n] monotonicity; this
            // closes the chain-tail-to-claim-payload gap.
            let last_granted = chain_clone
                .entries
                .last()
                .map(|e| e.granted_capabilities.clone())
                .unwrap_or_default();
            let claim_caps_set =
                CapabilitySet::from_kinds(received_claim.capabilities().iter().copied());
            if !last_granted.is_superset_of(&claim_caps_set) {
                return Err(ClaimVerificationError::ClaimExceedsChainTail);
            }
            Some(verified)
        }
    };

    // 15. Construct VerifiedCapabilityClaim.
    Ok(VerifiedCapabilityClaim::new_internal(
        issuer,
        subject,
        capabilities,
        resource_scope,
        trace_id_field,
        issued_at,
        expires_at,
        verified_chain,
    ))
}

/// Strip the `KryphocronClaim ` (case-insensitive) scheme prefix
/// per §7.6.
fn parse_claim_header(raw: &str) -> Result<&str, ClaimVerificationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ClaimVerificationError::Malformed);
    }
    if let Some(rest) = trimmed
        .strip_prefix("KryphocronClaim ")
        .or_else(|| trimmed.strip_prefix("kryphocronclaim "))
        .or_else(|| trimmed.strip_prefix("KRYPHOCRONCLAIM "))
    {
        let token = rest.trim_start();
        if token.is_empty() {
            return Err(ClaimVerificationError::Malformed);
        }
        return Ok(token);
    }
    // Bare token — operators that already stripped the scheme
    // upstream remain usable.
    Ok(trimmed)
}

/// Belt-and-suspenders class-vs-scope check at receive time
/// (§4.8 W9 / W10 enforcement). Mirror of `claim::check_scope_for_class`
/// expressed against [`crate::authority::CapabilityClass`].
fn class_permits_scope(
    class: crate::authority::CapabilityClass,
    scope: &ResourceScope,
) -> bool {
    use crate::authority::CapabilityClass;
    match class {
        CapabilityClass::User => matches!(scope, ResourceScope::Resource(_)),
        CapabilityClass::Channel => true,
        CapabilityClass::Substrate | CapabilityClass::Moderation => false,
    }
}

/// Pick a [`PublicKey`] from a resolved DID document for
/// capability-claim signature verification.
///
/// §7.6 dispatch: the issuer carries an explicit `KeyId`, so
/// resolution looks for an exact `KeyId` match in the DID
/// document's verification methods (or, in Phase 4c, the
/// rotation history). Algorithm must also match. No match →
/// `IssuerKeyNotInDocument`.
fn select_signing_key_for_claim(
    document: &crate::resolver::DidDocument,
    expected_key_id: KeyId,
    algorithm: SignatureAlgorithm,
) -> Result<PublicKey, ClaimVerificationError> {
    // Phase 4c: walk both the current
    // verification_methods AND the document's rotation_history.
    // §4.8 W12 commits rotation-tolerant verification — a claim
    // signed under a previously-active key still verifies if the
    // key is present in the resolved DID document's rotation
    // history. Exact-match-only would reject claims signed under
    // a key that was rotated out between issuance and verification,
    // even when the signature itself is cryptographically valid
    // against the historical key.
    for (kid, key) in document
        .verification_methods
        .iter()
        .chain(document.rotation_history.iter())
    {
        if *kid == expected_key_id && key.algorithm == algorithm {
            return Ok(*key);
        }
    }
    Err(ClaimVerificationError::IssuerKeyNotInDocument)
}

/// Verify a capability-claim signature for the given algorithm.
fn verify_claim_signature(
    signing_input: &[u8],
    signature: &[u8],
    algorithm: SignatureAlgorithm,
    public_key: &PublicKey,
) -> Result<(), ClaimVerificationError> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                return Err(ClaimVerificationError::SignatureInvalid);
            }
            let mut sig_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
            sig_bytes.copy_from_slice(signature);
            let sig = Ed25519Signature::from_bytes(&sig_bytes);
            let key = VerifyingKey::from_bytes(&public_key.bytes)
                .map_err(|_| ClaimVerificationError::SignatureInvalid)?;
            key.verify(signing_input, &sig)
                .map_err(|_| ClaimVerificationError::SignatureInvalid)
        }
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es256K => {
            // Phase 4a note: ES256/ES256K primitives
            // ship in a later sub-phase. Phase 4b keeps the same
            // stub posture for capability-claim verification.
            Err(ClaimVerificationError::UnsupportedAlgorithm(algorithm))
        }
    }
}

// ============================================================
// §7.5 — sync handshake verification.
// ============================================================

/// Verification configuration for §7.5 sync-handshake messages.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SyncHandshakeVerificationConfig {
    /// Maximum tolerated wallclock skew between peer-asserted `at`
    /// and verifier's `now`. Default 30 seconds, matching §7.2's
    /// JWT clock-skew default.
    pub max_clock_skew: Duration,
    /// Verifier's local lexicon-set version. Used by the
    /// responder-side Hello verifier for the major-version skew
    /// check committed in §5.5 / §7.5 line 6650-6660.
    pub local_lexicon_set_version: SemVer,
    /// Algorithm allowlist; default `[Ed25519]`. §7.5 does not
    /// commit additional algorithms for handshake signing.
    pub accepted_algorithms: &'static [SignatureAlgorithm],
}

impl Default for SyncHandshakeVerificationConfig {
    fn default() -> Self {
        SyncHandshakeVerificationConfig {
            max_clock_skew: Duration::from_secs(30),
            local_lexicon_set_version: SemVer::new(1, 0, 0),
            accepted_algorithms: &[SignatureAlgorithm::Ed25519],
        }
    }
}

/// §7.5 handshake verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SyncHandshakeVerificationError {
    /// Wire envelope structurally malformed (size, CBOR decode,
    /// non-canonical encoding, missing field, type mismatch).
    #[error("handshake message malformed")]
    Malformed,
    /// Message exceeded [`crate::wire::MAX_HANDSHAKE_MESSAGE_SIZE`].
    #[error("handshake message too large")]
    TooLarge,
    /// Handshake signature did not verify under the resolver-
    /// returned key material.
    #[error("handshake signature invalid")]
    SignatureInvalid,
    /// Counterparty DID resolution failed.
    #[error("handshake counterparty DID resolution failed: {0}")]
    CounterpartyResolutionFailed(DidResolutionError),
    /// Counterparty's claimed key id is not present in the
    /// resolved DID document (current methods or rotation history).
    #[error("counterparty key id not in DID document")]
    CounterpartyKeyNotInDocument,
    /// Algorithm not in the allowlist.
    #[error("handshake algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// Initiator's lexicon-set major version exceeds the
    /// responder's local major version (§5.5 / §7.5 line 6650).
    /// Responder-side; the responder's correct response is to
    /// emit a signed `SyncChannelResponse::Reject` with reason
    /// `LexiconSetMajorVersionMismatch`.
    #[error("initiator lexicon-set major version mismatch")]
    LexiconSetMajorVersionMismatch {
        /// Verifier's local version.
        local: SemVer,
        /// Initiator's claimed version.
        peer: SemVer,
    },
    /// Hello nonce was previously seen within the replay window.
    /// Responder-side; responder emits a signed reject with reason
    /// `HandshakeNonceReplay { first_seen_at }` and the
    /// `ChannelAuditEvent::SyncBatchRejected` audit event.
    #[error("handshake nonce replay")]
    HandshakeNonceReplay {
        /// Wallclock at which the responder first observed this
        /// nonce from this initiator.
        first_seen_at: SystemTime,
    },
    /// Backend failure consulting the [`HandshakeNonceTracker`].
    #[error("handshake nonce tracker backend unavailable: {0}")]
    NonceTrackerBackend(NonceTrackerError),
    /// `at` is more than `max_clock_skew` in the future.
    #[error("handshake `at` is in the future beyond skew tolerance")]
    NotYetValid,
    /// `at` is more than `max_clock_skew` in the past.
    #[error("handshake `at` is too old (clock skew exceeded)")]
    TooOld,
    /// Counterparty's identity does not match the expected
    /// identity for this side of the handshake. Returned by the
    /// initiator-side response verifier when the responder's
    /// `responder_identity` is not the DID the initiator sent
    /// Hello to (§7.5 "responder_identity unknown" → discard as
    /// no-message-received).
    #[error("counterparty identity mismatch")]
    CounterpartyIdentityMismatch,
}

/// §7.5 post-handshake message-verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SyncMessageVerificationError {
    /// Inner capability-claim verification failed.
    #[error("inner claim verification failed: {0}")]
    Claim(#[from] ClaimVerificationError),
    /// Verified claim's issuer does not match the session-bound
    /// peer identity. The substrate dispatcher closes the
    /// connection on this error; mid-session identity drift is a
    /// protocol violation.
    #[error("session-bound peer identity mismatch")]
    PeerIdentityMismatch,
}

/// Hello message that has passed responder-side §7.5 verification.
///
/// Constructible only via [`verify_sync_hello`].
#[derive(Debug, Clone)]
pub struct VerifiedSyncHello {
    initiator_identity: ServiceIdentity,
    initiator_lexicon_set_version: SemVer,
    proposed_session_nonce: SessionNonce,
    requested_scope: SyncRequestedScope,
    at: SystemTime,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedSyncHello {
    pub(crate) fn new_internal(
        initiator_identity: ServiceIdentity,
        initiator_lexicon_set_version: SemVer,
        proposed_session_nonce: SessionNonce,
        requested_scope: SyncRequestedScope,
        at: SystemTime,
    ) -> Self {
        VerifiedSyncHello {
            initiator_identity,
            initiator_lexicon_set_version,
            proposed_session_nonce,
            requested_scope,
            at,
            _private: PhantomData,
        }
    }
    /// Borrow the initiator identity.
    #[must_use]
    pub fn initiator_identity(&self) -> &ServiceIdentity {
        &self.initiator_identity
    }
    /// Initiator's lexicon-set version.
    #[must_use]
    pub fn initiator_lexicon_set_version(&self) -> SemVer {
        self.initiator_lexicon_set_version
    }
    /// Borrow the proposed session nonce.
    #[must_use]
    pub fn proposed_session_nonce(&self) -> &SessionNonce {
        &self.proposed_session_nonce
    }
    /// The scope requested by the initiator, **before** any §7.5
    /// federation narrowing has been applied.
    ///
    /// **WARNING: do not use for access control.** Federation
    /// peers (`PeerKind::Federation`) requesting `time_window:
    /// None` are subject to §7.5 line 6616's MUST-apply 7-day
    /// narrowing under [`crate::wire::DEFAULT_FEDERATION_TIME_WINDOW`].
    /// Internal peers (`PeerKind::Internal`) are exempt. The raw
    /// requested scope returned here is appropriate for audit
    /// logging only — for access-control decisions, ALWAYS call
    /// [`Self::narrowed_scope`] with the resolved peer kind.
    #[must_use]
    pub fn requested_scope(&self) -> &SyncRequestedScope {
        &self.requested_scope
    }
    /// The scope after §7.5 federation narrowing has been applied
    /// based on the resolved peer kind and any
    /// `TrustedWithConstraints` override.
    ///
    /// **THIS is what access-control code must consume.** The
    /// narrowing rules:
    ///
    /// - `PeerKind::Internal` → returns the requested scope
    ///   unchanged. Substrate-internal components are exempt from
    ///   the federation default per §7.5 line 6634.
    /// - `PeerKind::Federation` + non-`None` `time_window` →
    ///   returns the requested scope unchanged (the initiator
    ///   already supplied a bound).
    /// - `PeerKind::Federation` + `time_window: None` + no
    ///   operator-policy override → narrows to `Some(SyncTimeWindow
    ///   { start: now - DEFAULT_FEDERATION_TIME_WINDOW, end: now })`
    ///   per §7.5 line 6616-6626.
    /// - `PeerKind::Federation` + operator-supplied
    ///   `PeerTrustConstraints` (Phase 4 placeholder; constraint-
    ///   shape-extension lands in §7.7 Phase 4f or later) →
    ///   honors the operator constraint over the default. The
    ///   current `PeerTrustConstraints` is an empty struct (§7.7
    ///   commitment with no field shape yet); when fields land,
    ///   the override path activates here.
    ///
    /// `now` is supplied by the caller so test fixtures and
    /// deterministic-clock callers can pin behavior; production
    /// callers pass `SystemTime::now()`.
    #[must_use]
    pub fn narrowed_scope(
        &self,
        peer_kind: crate::resolver::PeerKind,
        _constraints: Option<&crate::audit::PeerTrustConstraints>,
        now: SystemTime,
    ) -> SyncRequestedScope {
        use crate::resolver::PeerKind;
        use crate::wire::{SyncTimeWindow, DEFAULT_FEDERATION_TIME_WINDOW};

        match peer_kind {
            PeerKind::Internal => self.requested_scope.clone(),
            PeerKind::Federation => {
                if self.requested_scope.time_window.is_some() {
                    self.requested_scope.clone()
                } else {
                    // §7.5 line 6616 narrowing: time_window: None
                    // → 7-day window ending now. Operator
                    // constraint override would activate here once
                    // PeerTrustConstraints carries
                    // `max_sync_scope` (Phase 4f or later); current
                    // `_constraints` parameter is reserved.
                    let mut narrowed = self.requested_scope.clone();
                    let start = now
                        .checked_sub(DEFAULT_FEDERATION_TIME_WINDOW)
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    narrowed.time_window = Some(SyncTimeWindow {
                        start,
                        end: now,
                    });
                    narrowed
                }
            }
        }
    }
    /// Wallclock the initiator stamped.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        self.at
    }
}

/// Accept message that has passed initiator-side §7.5 verification.
#[derive(Debug, Clone)]
pub struct VerifiedSyncAccept {
    responder_identity: ServiceIdentity,
    responder_lexicon_set_version: SemVer,
    session_id: SessionId,
    negotiated_scope: SyncRequestedScope,
    at: SystemTime,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedSyncAccept {
    pub(crate) fn new_internal(
        responder_identity: ServiceIdentity,
        responder_lexicon_set_version: SemVer,
        session_id: SessionId,
        negotiated_scope: SyncRequestedScope,
        at: SystemTime,
    ) -> Self {
        VerifiedSyncAccept {
            responder_identity,
            responder_lexicon_set_version,
            session_id,
            negotiated_scope,
            at,
            _private: PhantomData,
        }
    }
    /// Borrow the responder identity.
    #[must_use]
    pub fn responder_identity(&self) -> &ServiceIdentity {
        &self.responder_identity
    }
    /// Responder's lexicon-set version.
    #[must_use]
    pub fn responder_lexicon_set_version(&self) -> SemVer {
        self.responder_lexicon_set_version
    }
    /// Session id derived by the responder.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    /// Borrow the negotiated (responder-narrowed) scope.
    #[must_use]
    pub fn negotiated_scope(&self) -> &SyncRequestedScope {
        &self.negotiated_scope
    }
    /// Wallclock the responder stamped.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        self.at
    }
}

/// Reject message that has passed initiator-side §7.5 verification.
#[derive(Debug, Clone)]
pub struct VerifiedSyncReject {
    reason: BatchRejectionReason,
    responder_identity: ServiceIdentity,
    at: SystemTime,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedSyncReject {
    pub(crate) fn new_internal(
        reason: BatchRejectionReason,
        responder_identity: ServiceIdentity,
        at: SystemTime,
    ) -> Self {
        VerifiedSyncReject {
            reason,
            responder_identity,
            at,
            _private: PhantomData,
        }
    }
    /// Borrow the rejection reason.
    #[must_use]
    pub fn reason(&self) -> &BatchRejectionReason {
        &self.reason
    }
    /// Borrow the responder identity.
    #[must_use]
    pub fn responder_identity(&self) -> &ServiceIdentity {
        &self.responder_identity
    }
    /// Wallclock the responder stamped.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        self.at
    }
}

/// Verified Response: Accept or Reject (§7.5).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifiedSyncResponse {
    /// The handshake was accepted.
    Accept(VerifiedSyncAccept),
    /// The handshake was rejected with a signed reason.
    Reject(VerifiedSyncReject),
}

/// Established message that has passed responder-side §7.5
/// verification.
#[derive(Debug, Clone)]
pub struct VerifiedSyncEstablished {
    session_id: SessionId,
    at: SystemTime,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedSyncEstablished {
    pub(crate) fn new_internal(session_id: SessionId, at: SystemTime) -> Self {
        VerifiedSyncEstablished {
            session_id,
            at,
            _private: PhantomData,
        }
    }
    /// Session id from the bound session.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    /// Wallclock the initiator stamped.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        self.at
    }
}

// Phase 4d wires VerifiedSyncMessage's previously-unreachable
// constructor path. Kept `pub(crate)` so only the verifier in this
// module can produce one.
impl VerifiedSyncMessage {
    pub(crate) fn new_internal(
        session_identity: ServiceIdentity,
        session_id: SessionId,
        payload: VerifiedCapabilityClaim,
    ) -> Self {
        VerifiedSyncMessage {
            session_identity,
            session_id,
            payload,
            _private: PhantomData,
        }
    }
}

/// Responder-side verifier for `SyncChannelHello` (§7.5).
///
/// Walks the §7.5 verification chain in fail-closed order:
///
/// 1. Size + canonical-CBOR round-trip canonicality (Phase 4b's
///    §7 round-4 hazard discipline applied symmetrically).
/// 2. CBOR decode into structured fields plus the carried
///    signature.
/// 3. Algorithm allowlist enforcement (default `[Ed25519]`).
/// 4. Clock-skew bounds on the initiator's `at`.
/// 5. Major-version skew check against the verifier's local
///    lexicon-set version.
/// 6. Counterparty DID resolution + signing-key selection (walks
///    `verification_methods` AND `rotation_history` per §4.8 W12).
/// 7. Signature verification under [`crate::wire::HELLO_DOMAIN_TAG`].
/// 8. Nonce-tracker check_and_record. The nonce check happens AFTER
///    signature verification so an attacker cannot induce nonce-
///    table churn without first producing a valid signature.
///
/// On success, returns [`VerifiedSyncHello`] sealed-by-construction.
/// On any verification failure, returns the appropriate variant of
/// [`SyncHandshakeVerificationError`].
///
/// # Errors
///
/// Returns [`SyncHandshakeVerificationError`] for any failure.
pub async fn verify_sync_hello(
    wire_bytes: &[u8],
    nonce_tracker: &dyn HandshakeNonceTracker,
    resolver: &dyn DidResolver,
    config: &SyncHandshakeVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<VerifiedSyncHello, SyncHandshakeVerificationError> {
    if wire_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(SyncHandshakeVerificationError::TooLarge);
    }
    if !handshake_wire_is_canonical_hello(wire_bytes) {
        return Err(SyncHandshakeVerificationError::Malformed);
    }
    let (initiator_identity, initiator_ver, nonce, scope, at, signature) =
        decode_hello_wire(wire_bytes)
            .map_err(|()| SyncHandshakeVerificationError::Malformed)?;

    if !config.accepted_algorithms.contains(&signature.algorithm) {
        return Err(SyncHandshakeVerificationError::UnsupportedAlgorithm(
            signature.algorithm,
        ));
    }

    let now = SystemTime::now();
    check_at_window(at, now, config.max_clock_skew)?;

    if initiator_ver.major > config.local_lexicon_set_version.major {
        return Err(
            SyncHandshakeVerificationError::LexiconSetMajorVersionMismatch {
                local: config.local_lexicon_set_version,
                peer: initiator_ver,
            },
        );
    }

    let document = resolver
        .resolve(initiator_identity.service_did(), deadline, trace_id)
        .await
        .map_err(SyncHandshakeVerificationError::CounterpartyResolutionFailed)?;
    let public_key = select_handshake_signing_key(
        &document,
        initiator_identity.key_id(),
        signature.algorithm,
    )?;

    let sign_input = crate::wire::hello_sign_input(
        &initiator_identity,
        initiator_ver,
        &nonce,
        &scope,
        at,
    );
    if !crate::wire::verify_handshake_signature(&public_key, &sign_input, &signature) {
        return Err(SyncHandshakeVerificationError::SignatureInvalid);
    }

    // Nonce tracking AFTER signature verification: an attacker
    // forging a signature can no longer induce nonce-table churn,
    // and a legitimate replay surfaces the recorded `first_seen_at`
    // for the audit event.
    match nonce_tracker.check_and_record(&initiator_identity, &nonce, now) {
        Ok(NonceFreshness::Fresh) => {}
        Ok(NonceFreshness::Replay { first_seen_at }) => {
            return Err(SyncHandshakeVerificationError::HandshakeNonceReplay {
                first_seen_at,
            });
        }
        Err(e) => {
            return Err(SyncHandshakeVerificationError::NonceTrackerBackend(e));
        }
    }

    Ok(VerifiedSyncHello::new_internal(
        initiator_identity,
        initiator_ver,
        nonce,
        scope,
        at,
    ))
}

/// Initiator-side verifier for `SyncChannelResponse` (§7.5).
///
/// Routes by wire-decode into Accept or Reject branch and verifies
/// the responder's signature under [`crate::wire::ACCEPT_DOMAIN_TAG`] or
/// [`crate::wire::REJECT_DOMAIN_TAG`] respectively. The `expected_responder_did`
/// is the DID the initiator sent Hello to; per §7.5's "responder_
/// identity unknown is discarded as no-message-received" prose,
/// any responder identity that doesn't match this expected DID
/// returns [`SyncHandshakeVerificationError::CounterpartyIdentityMismatch`].
///
/// The wire bytes carry an outer 1-byte discriminator (0x00 for
/// Accept, 0x01 for Reject) prepended to the message bytes; this
/// is the substrate's framing choice for the on-wire envelope.
///
/// # Errors
///
/// Returns [`SyncHandshakeVerificationError`] for any failure.
pub async fn verify_sync_response(
    wire_bytes: &[u8],
    expected_responder_did: &Did,
    resolver: &dyn DidResolver,
    config: &SyncHandshakeVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<VerifiedSyncResponse, SyncHandshakeVerificationError> {
    if wire_bytes.is_empty() {
        return Err(SyncHandshakeVerificationError::Malformed);
    }
    let (discriminator, body) = wire_bytes.split_first().expect("non-empty");
    match discriminator {
        0x00 => verify_sync_accept(body, expected_responder_did, resolver, config, deadline, trace_id)
            .await
            .map(VerifiedSyncResponse::Accept),
        0x01 => verify_sync_reject(body, expected_responder_did, resolver, config, deadline, trace_id)
            .await
            .map(VerifiedSyncResponse::Reject),
        _ => Err(SyncHandshakeVerificationError::Malformed),
    }
}

async fn verify_sync_accept(
    wire_bytes: &[u8],
    expected_responder_did: &Did,
    resolver: &dyn DidResolver,
    config: &SyncHandshakeVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<VerifiedSyncAccept, SyncHandshakeVerificationError> {
    if wire_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(SyncHandshakeVerificationError::TooLarge);
    }
    if !handshake_wire_is_canonical_accept(wire_bytes) {
        return Err(SyncHandshakeVerificationError::Malformed);
    }
    let (responder_identity, responder_ver, session_id, negotiated_scope, at, signature) =
        decode_accept_wire(wire_bytes)
            .map_err(|()| SyncHandshakeVerificationError::Malformed)?;

    if responder_identity.service_did() != expected_responder_did {
        return Err(SyncHandshakeVerificationError::CounterpartyIdentityMismatch);
    }
    if !config.accepted_algorithms.contains(&signature.algorithm) {
        return Err(SyncHandshakeVerificationError::UnsupportedAlgorithm(
            signature.algorithm,
        ));
    }
    check_at_window(at, SystemTime::now(), config.max_clock_skew)?;

    let document = resolver
        .resolve(expected_responder_did, deadline, trace_id)
        .await
        .map_err(SyncHandshakeVerificationError::CounterpartyResolutionFailed)?;
    let public_key = select_handshake_signing_key(
        &document,
        responder_identity.key_id(),
        signature.algorithm,
    )?;
    let sign_input = crate::wire::accept_sign_input(
        &responder_identity,
        responder_ver,
        &session_id,
        &negotiated_scope,
        at,
    );
    if !crate::wire::verify_handshake_signature(&public_key, &sign_input, &signature) {
        return Err(SyncHandshakeVerificationError::SignatureInvalid);
    }

    Ok(VerifiedSyncAccept::new_internal(
        responder_identity,
        responder_ver,
        session_id,
        negotiated_scope,
        at,
    ))
}

async fn verify_sync_reject(
    wire_bytes: &[u8],
    expected_responder_did: &Did,
    resolver: &dyn DidResolver,
    config: &SyncHandshakeVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<VerifiedSyncReject, SyncHandshakeVerificationError> {
    if wire_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(SyncHandshakeVerificationError::TooLarge);
    }
    if !handshake_wire_is_canonical_reject(wire_bytes) {
        return Err(SyncHandshakeVerificationError::Malformed);
    }
    let (reason, responder_identity, at, signature) = decode_reject_wire(wire_bytes)
        .map_err(|()| SyncHandshakeVerificationError::Malformed)?;

    if responder_identity.service_did() != expected_responder_did {
        return Err(SyncHandshakeVerificationError::CounterpartyIdentityMismatch);
    }
    if !config.accepted_algorithms.contains(&signature.algorithm) {
        return Err(SyncHandshakeVerificationError::UnsupportedAlgorithm(
            signature.algorithm,
        ));
    }
    check_at_window(at, SystemTime::now(), config.max_clock_skew)?;

    let document = resolver
        .resolve(expected_responder_did, deadline, trace_id)
        .await
        .map_err(SyncHandshakeVerificationError::CounterpartyResolutionFailed)?;
    let public_key = select_handshake_signing_key(
        &document,
        responder_identity.key_id(),
        signature.algorithm,
    )?;
    let sign_input = crate::wire::reject_sign_input(&reason, &responder_identity, at);
    if !crate::wire::verify_handshake_signature(&public_key, &sign_input, &signature) {
        return Err(SyncHandshakeVerificationError::SignatureInvalid);
    }

    Ok(VerifiedSyncReject::new_internal(reason, responder_identity, at))
}

/// Responder-side verifier for `SyncChannelEstablished` (§7.5).
///
/// The responder verifies the initiator's signature over
/// `(session_id, responder_identity = self_identity, at)` under
/// [`crate::wire::ESTABLISHED_DOMAIN_TAG`]. The responder's own identity is
/// supplied as `local_identity`; the initiator's verifying key
/// must come from the prior Hello-time DID resolution (`initiator_
/// public_key`) since Established's wire envelope does NOT carry
/// the initiator identity.
///
/// # Errors
///
/// Returns [`SyncHandshakeVerificationError`] for any failure.
pub fn verify_sync_established(
    wire_bytes: &[u8],
    local_identity: &ServiceIdentity,
    initiator_public_key: &PublicKey,
    config: &SyncHandshakeVerificationConfig,
) -> Result<VerifiedSyncEstablished, SyncHandshakeVerificationError> {
    if wire_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(SyncHandshakeVerificationError::TooLarge);
    }
    if !handshake_wire_is_canonical_established(wire_bytes) {
        return Err(SyncHandshakeVerificationError::Malformed);
    }
    let (session_id, at, signature) = decode_established_wire(wire_bytes)
        .map_err(|()| SyncHandshakeVerificationError::Malformed)?;
    if !config.accepted_algorithms.contains(&signature.algorithm) {
        return Err(SyncHandshakeVerificationError::UnsupportedAlgorithm(
            signature.algorithm,
        ));
    }
    check_at_window(at, SystemTime::now(), config.max_clock_skew)?;

    let sign_input = crate::wire::established_sign_input(&session_id, local_identity, at);
    if !crate::wire::verify_handshake_signature(initiator_public_key, &sign_input, &signature) {
        return Err(SyncHandshakeVerificationError::SignatureInvalid);
    }
    Ok(VerifiedSyncEstablished::new_internal(session_id, at))
}

/// Verify a post-handshake §7.6 capability claim that arrived on
/// an established sync channel.
///
/// Wraps [`verify_capability_claim`] and additionally enforces that
/// the verified claim's issuer matches the session-bound peer
/// identity (`session_peer`). Mid-session identity drift is a
/// protocol violation and surfaces as
/// [`SyncMessageVerificationError::PeerIdentityMismatch`].
///
/// The substrate dispatcher (or its sync-message handler) is
/// responsible for the §7.5 `UnknownSessionMessage` audit emit
/// when a sync-channel message arrives with a session id not in
/// the local session table; this function operates on already-
/// looked-up session state.
///
/// # Errors
///
/// Returns [`SyncMessageVerificationError`] for any failure.
pub async fn verify_sync_message(
    raw_header: &str,
    session_id: SessionId,
    session_peer: &ServiceIdentity,
    local_audience: &ServiceIdentity,
    resolver: &dyn DidResolver,
    nonce_tracker: &dyn NonceTracker,
    config: &ClaimVerificationConfig,
    deadline: Instant,
    trace_id: TraceId,
    origin_authorized_capabilities: &CapabilitySet,
) -> Result<VerifiedSyncMessage, SyncMessageVerificationError> {
    let claim = verify_capability_claim(
        raw_header,
        local_audience,
        resolver,
        nonce_tracker,
        config,
        deadline,
        trace_id,
        origin_authorized_capabilities,
    )
    .await?;
    if claim.issuer() != session_peer {
        return Err(SyncMessageVerificationError::PeerIdentityMismatch);
    }
    Ok(VerifiedSyncMessage::new_internal(
        session_peer.clone(),
        session_id,
        claim,
    ))
}

// ============================================================
// §7.5 internal helpers.
// ============================================================

fn check_at_window(
    at: SystemTime,
    now: SystemTime,
    skew: Duration,
) -> Result<(), SyncHandshakeVerificationError> {
    if at > now + skew {
        return Err(SyncHandshakeVerificationError::NotYetValid);
    }
    // Reject `at` more than one skew window in the past — handshake
    // messages are expected to be near-real-time. Operators with
    // looser `at` semantics configure a wider `max_clock_skew`.
    if let Ok(age) = now.duration_since(at) {
        if age > skew {
            return Err(SyncHandshakeVerificationError::TooOld);
        }
    }
    Ok(())
}

fn select_handshake_signing_key(
    document: &crate::resolver::DidDocument,
    expected_key_id: KeyId,
    algorithm: SignatureAlgorithm,
) -> Result<PublicKey, SyncHandshakeVerificationError> {
    for (kid, key) in document
        .verification_methods
        .iter()
        .chain(document.rotation_history.iter())
    {
        if *kid == expected_key_id && key.algorithm == algorithm {
            return Ok(*key);
        }
    }
    Err(SyncHandshakeVerificationError::CounterpartyKeyNotInDocument)
}

fn handshake_wire_is_canonical_hello(bytes: &[u8]) -> bool {
    decode_hello_wire(bytes)
        .ok()
        .map(|d| {
            let h = SyncChannelHello {
                initiator_identity: d.0,
                initiator_lexicon_set_version: d.1,
                proposed_session_nonce: d.2,
                requested_scope: d.3,
                at: d.4,
                initiator_signature: d.5,
            };
            hello_to_wire_bytes(&h) == bytes
        })
        .unwrap_or(false)
}

fn handshake_wire_is_canonical_accept(bytes: &[u8]) -> bool {
    decode_accept_wire(bytes)
        .ok()
        .map(|d| {
            let a = SyncChannelAccept {
                responder_identity: d.0,
                responder_lexicon_set_version: d.1,
                session_id: d.2,
                negotiated_scope: d.3,
                at: d.4,
                responder_signature: d.5,
            };
            accept_to_wire_bytes(&a) == bytes
        })
        .unwrap_or(false)
}

fn handshake_wire_is_canonical_reject(bytes: &[u8]) -> bool {
    decode_reject_wire(bytes)
        .ok()
        .map(|d| {
            let r = SyncChannelReject {
                reason: d.0,
                responder_identity: d.1,
                at: d.2,
                responder_signature: d.3,
            };
            reject_to_wire_bytes(&r) == bytes
        })
        .unwrap_or(false)
}

fn handshake_wire_is_canonical_established(bytes: &[u8]) -> bool {
    decode_established_wire(bytes)
        .ok()
        .map(|d| {
            let e = SyncChannelEstablished {
                session_id: d.0,
                at: d.1,
                initiator_signature: d.2,
            };
            established_to_wire_bytes(&e) == bytes
        })
        .unwrap_or(false)
}

// ============================================================
// §4.8 W11 / W12 / W13 — attribution chain verification.
// ============================================================

/// Verify a wire-form attribution chain into a verified
/// [`crate::AttributionChain`] (§4.8 W11 / W12 / W13).
///
/// The eight-stage chain:
///
/// 1. **Depth bound:** `chain_wire.entries.len()` ≤
///    `MAX_CHAIN_DEPTH` (8) per §4.2 / §4.8.
/// 2. **Per-hop loop, in order from i = 0:**
///    1. Identify `previous_principal` — `chain_wire.origin` for
///       i = 0, otherwise `chain_wire.entries[i-1].principal`.
///    2. Resolve previous principal's DID via `DidResolver::resolve(_, trace_id)`.
///    3. **W12 algorithm check:** receipt's algorithm in allowlist
///       → else `AlgorithmNotAccepted`.
///    4. **W12 rotation tolerance + key discovery:** walk the
///       resolved DID document's `verification_methods +
///       rotation_history`. For each candidate `(key_id, key)`
///       reconstruct the canonical `DelegationReceiptPayload` with
///       `previous_key_id = key_id`, attempt signature verification.
///       The first that verifies is the signing key for this hop.
///       (Trial verification: at most
///       `MAX_ROTATION_DEPTH × MAX_CHAIN_DEPTH` Ed25519 verifies
///       per chain.)
///    5. **W12 fail modes:** no candidate verified → if any key
///       was tried under the wrong algorithm,
///       `KeyNotInRotationHistory`; if signatures were tried but
///       all failed, `SignatureInvalid`.
///    6. **W13 monotonicity:** `entries[i].granted_capabilities`
///       ⊆ `previous_authorized_capabilities` (where the previous
///       authorized set is `origin_authorized_capabilities` for
///       i = 0, else `entries[i-1].granted_capabilities`). Else
///       `CapabilityExpansion { hop, attempted, available }`.
///    7. Update `previous_authorized_capabilities` to the current
///       hop's `granted_capabilities` for the next iteration.
/// 3. Build the verified [`crate::AttributionChain`] from the wire
///    form by walking each verified hop into a
///    [`crate::AttributionEntry`].
///
/// **Fail-fast at the first failing hop.** §4.8 W13 commits the
/// `failing_hop` index in [`BindError::AttributionReceiptInvalid`]
/// as a lower bound on chain failure extent, not exhaustive.
///
/// **Timing equalization considered.** §4.6's `equalize_timing`
/// discipline absorbs the hop-by-hop variance at the consuming
/// bind paths. This verifier does NOT add equalization plumbing
/// itself — the bind paths that consume the verified chain pull
/// in equalization for the capability classes that need it.
///
/// **Pattern B authority plumbing.** The
/// `origin_authorized_capabilities` parameter is supplied by the
/// caller (typically [`verify_capability_claim`] derived from the
/// originating JWT scope or service-claim authority). The
/// alternative ("Pattern A": chain root carries the authority via
/// extended `DerivationReason` variants) was considered and
/// declined for Phase 4e — see the Phase 4e completion report.
///
/// # Errors
///
/// Returns [`BindError::AttributionReceiptInvalid`] for any
/// receipt-verification failure with the failing hop index and
/// the specific [`ReceiptVerificationFailure`] variant.
pub async fn verify_attribution_chain(
    chain_wire: &AttributionChainWire,
    origin_authorized_capabilities: &CapabilitySet,
    resolver: &dyn DidResolver,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<crate::AttributionChain, BindError> {
    // Stage 1: depth bound.
    if chain_wire.entries.len() > crate::ingress::MAX_CHAIN_DEPTH {
        return Err(BindError::AttributionReceiptInvalid {
            failing_hop: chain_wire.entries.len() as u8,
            reason: ReceiptVerificationFailure::Malformed,
        });
    }

    let static_allowlist: &[SignatureAlgorithm] = &[SignatureAlgorithm::Ed25519];

    let mut previous_principal: AttributionPrincipalRef<'_> =
        AttributionPrincipalRef::FromOrigin(&chain_wire.origin);
    let mut previous_authorized = origin_authorized_capabilities.clone();
    let mut verified_entries: Vec<crate::AttributionEntry> = Vec::new();

    for (hop_index, entry) in chain_wire.entries.iter().enumerate() {
        let hop = u8::try_from(hop_index).unwrap_or(u8::MAX);

        verify_hop(
            entry,
            hop,
            &previous_principal,
            &previous_authorized,
            static_allowlist,
            resolver,
            deadline,
            trace_id,
        )
        .await
        .map_err(|reason| BindError::AttributionReceiptInvalid {
            failing_hop: hop,
            reason,
        })?;

        // The verified hop becomes an in-process AttributionEntry.
        // The signing key id used at this hop is captured during
        // verify_hop's trial-verification; for the in-process
        // chain we record the recipient's key_id (which is what the
        // §4.2 chain shape pins).
        let key_id_used = entry.principal.key_id();
        verified_entries.push(crate::AttributionEntry {
            requester: principal_to_requester(&entry.principal),
            derivation_reason: entry.derivation_reason.clone(),
            derived_at: entry.derived_at,
            key_id_used,
        });

        previous_principal = AttributionPrincipalRef::FromEntry(&entry.principal);
        previous_authorized = entry.granted_capabilities.clone();
    }

    // Build the in-process AttributionChain from the verified
    // entries. The chain's depth invariant is enforced by the
    // crate-internal try_push helper.
    let mut chain = crate::AttributionChain::empty();
    for entry in verified_entries {
        chain
            .try_push(entry)
            .map_err(|_| BindError::AttributionReceiptInvalid {
                failing_hop: chain_wire.entries.len() as u8,
                reason: ReceiptVerificationFailure::Malformed,
            })?;
    }
    Ok(chain)
}

#[allow(clippy::too_many_arguments)]
async fn verify_hop(
    entry: &AttributionEntryWire,
    hop: u8,
    previous_principal: &AttributionPrincipalRef<'_>,
    previous_authorized: &CapabilitySet,
    accepted_algorithms: &[SignatureAlgorithm],
    resolver: &dyn DidResolver,
    deadline: Instant,
    trace_id: TraceId,
) -> Result<(), ReceiptVerificationFailure> {
    // 2c — algorithm allowlist.
    if !accepted_algorithms.contains(&entry.receipt.algorithm) {
        return Err(ReceiptVerificationFailure::AlgorithmNotAccepted(
            entry.receipt.algorithm,
        ));
    }

    // 2b — resolve previous principal's DID document.
    let previous_did = previous_principal.did();
    let document = resolver
        .resolve(previous_did, deadline, trace_id)
        .await
        .map_err(ReceiptVerificationFailure::PreviousPrincipalUnresolvable)?;

    // 2d — trial verification across the previous principal's
    // current methods + rotation history. The first key whose
    // canonical reconstruction signature-verifies is the signing
    // key for this hop.
    let recipient_did = entry.principal.did().clone();
    let recipient_key_id = entry.principal.key_id().unwrap_or(KeyId::from_bytes([0u8; 32]));

    let mut tried_any_key = false;
    let mut tried_matching_alg = false;
    for (candidate_key_id, candidate_key) in document
        .verification_methods
        .iter()
        .chain(document.rotation_history.iter())
    {
        tried_any_key = true;
        if candidate_key.algorithm != entry.receipt.algorithm {
            continue;
        }
        tried_matching_alg = true;

        let payload = DelegationReceiptPayload {
            previous_principal_did: previous_did.clone(),
            previous_key_id: *candidate_key_id,
            recipient_principal_did: recipient_did.clone(),
            recipient_key_id,
            derivation_reason: entry.derivation_reason.clone(),
            granted_capabilities: entry.granted_capabilities.clone(),
            derived_at: entry.derived_at,
        };
        if verify_delegation_receipt(&payload, &entry.receipt, candidate_key) {
            // 2f — W13 monotonicity check. Apply AFTER signature
            // verification: a forged signature would be rejected
            // before the monotonicity check has a chance to run.
            if !previous_authorized.is_superset_of(&entry.granted_capabilities) {
                return Err(ReceiptVerificationFailure::CapabilityExpansion {
                    hop,
                    attempted: entry.granted_capabilities.clone(),
                    available: previous_authorized.clone(),
                });
            }
            return Ok(());
        }
    }

    if !tried_any_key {
        // Document had no keys at all — treat as the resolved
        // principal having no signing key id we can verify
        // against.
        return Err(ReceiptVerificationFailure::KeyNotInRotationHistory {
            previous_key_id: KeyId::from_bytes([0u8; 32]),
        });
    }
    if !tried_matching_alg {
        // No keys with the receipt's algorithm — closest fit is
        // KeyNotInRotationHistory because the algorithm match is
        // structural (a key's algorithm tag is part of its
        // identity in the rotation set).
        return Err(ReceiptVerificationFailure::KeyNotInRotationHistory {
            previous_key_id: KeyId::from_bytes([0u8; 32]),
        });
    }
    Err(ReceiptVerificationFailure::SignatureInvalid)
}

/// Borrowed previous-principal accessor used inside the per-hop
/// loop. Lets the loop carry either an [`AttributionPrincipal`]
/// owned by `chain_wire.origin` or one borrowed from the prior
/// entry without cloning.
enum AttributionPrincipalRef<'a> {
    FromOrigin(&'a AttributionPrincipal),
    FromEntry(&'a AttributionPrincipal),
}

impl<'a> AttributionPrincipalRef<'a> {
    fn did(&self) -> &Did {
        match self {
            AttributionPrincipalRef::FromOrigin(p) | AttributionPrincipalRef::FromEntry(p) => {
                p.did()
            }
        }
    }
}

fn principal_to_requester(p: &AttributionPrincipal) -> crate::ingress::Requester {
    match p {
        AttributionPrincipal::User(did) => crate::ingress::Requester::Did(did.clone()),
        AttributionPrincipal::Service(s) => crate::ingress::Requester::Service(s.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::{Arc, Mutex};

    use crate::resolver::{DidDocument, DidResolutionError, DidResolver};

    // ============================================================
    // Test fixtures.
    // ============================================================

    fn local_audience() -> ServiceIdentity {
        ServiceIdentity::new_internal(
            Did::new("did:web:audience.example").unwrap(),
            KeyId::from_bytes([0u8; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn issuer_did() -> Did {
        Did::new("did:plc:issuerexample").unwrap()
    }

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn fixed_verifying_pubkey() -> PublicKey {
        let signing = fixed_signing_key();
        PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: signing.verifying_key().to_bytes(),
        }
    }

    fn b64u(input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    /// Construct + sign a JWT from a header JSON + payload JSON.
    fn build_jwt(header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let header_b64 = b64u(serde_json::to_vec(header).unwrap().as_slice());
        let payload_b64 = b64u(serde_json::to_vec(payload).unwrap().as_slice());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = fixed_signing_key().sign(signing_input.as_bytes());
        let sig_b64 = b64u(&sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    fn standard_payload(now_secs: u64) -> serde_json::Value {
        serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": local_audience().service_did().as_str(),
            "iat": now_secs,
            "exp": now_secs + 600,
            "scope": "tools.kryphocron.feed.read",
        })
    }

    fn ed25519_header() -> serde_json::Value {
        serde_json::json!({ "alg": "EdDSA", "typ": "JWT" })
    }

    // ============================================================
    // Mock DidResolver.
    // ============================================================

    /// In-memory mock resolver. Stores DID → (key id, public key)
    /// pairs; configurable to also return errors.
    struct MockResolver {
        documents: Mutex<std::collections::HashMap<String, Result<DidDocument, DidResolutionError>>>,
    }

    impl MockResolver {
        fn new() -> Self {
            MockResolver {
                documents: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn insert(&self, did: &Did, key_id: KeyId, key: PublicKey) {
            let doc = DidDocument {
                did: did.clone(),
                verification_methods: vec![(key_id, key)],
                rotation_history: vec![],
                services: vec![],
                also_known_as: vec![],
                resolved_at: SystemTime::now(),
                resolver_cache_max_age: Duration::from_secs(3600),
            };
            self.documents.lock().unwrap().insert(did.as_str().to_string(), Ok(doc));
        }

        fn insert_err(&self, did: &Did, err: DidResolutionError) {
            self.documents.lock().unwrap().insert(did.as_str().to_string(), Err(err));
        }
    }

    #[async_trait]
    impl DidResolver for MockResolver {
        async fn resolve(
            &self,
            did: &Did,
            _deadline: Instant,
            _trace_id: TraceId,
        ) -> Result<DidDocument, DidResolutionError> {
            self.documents
                .lock()
                .unwrap()
                .get(did.as_str())
                .cloned()
                .unwrap_or(Err(DidResolutionError::NotFound))
        }

        async fn invalidate(&self, _did: &Did, _trace_id: TraceId) {}
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn populated_resolver() -> Arc<MockResolver> {
        let resolver = Arc::new(MockResolver::new());
        resolver.insert(&issuer_did(), KeyId::from_bytes([1u8; 32]), fixed_verifying_pubkey());
        resolver
    }

    // ============================================================
    // §7.2 default-config commitments.
    // ============================================================

    #[test]
    fn jwt_config_default_is_ed25519_only() {
        // §7.2 default allowlist commitment.
        let c = JwtVerificationConfig::default();
        assert_eq!(c.accepted_algorithms, &[SignatureAlgorithm::Ed25519]);
        assert!(!c.require_nonce);
    }

    #[test]
    fn jwt_config_defaults_match_7_2_recommendations() {
        let c = JwtVerificationConfig::default();
        assert_eq!(c.max_clock_skew, Duration::from_secs(30));
        assert_eq!(c.max_validity_window, Duration::from_secs(3600));
    }

    // ============================================================
    // §7.2 parsing tests.
    // ============================================================

    #[tokio::test]
    async fn malformed_jwt_with_wrong_segment_count_returns_malformed() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        for bad in ["", "only_one_segment", "two.segments", "four.segments.are.bad"] {
            let err = verify_jwt(bad, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
                .await
                .unwrap_err();
            assert!(matches!(err, JwtVerificationError::Malformed), "input {bad:?} -> {err:?}");
        }
    }

    #[tokio::test]
    async fn malformed_jwt_with_invalid_base64url_returns_malformed() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        // `***` is not valid base64url.
        let err = verify_jwt("***.***.***", &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::Malformed));
    }

    #[tokio::test]
    async fn malformed_jwt_with_invalid_json_in_header_returns_malformed() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let bad = format!("{}.{}.{}", b64u(b"not json"), b64u(b"{}"), b64u(b"sig"));
        let err = verify_jwt(&bad, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::Malformed));
    }

    #[tokio::test]
    async fn alg_none_returns_malformed_not_unsupported() {
        // §7.2 alg-confusion discipline: `alg: "none"` → Malformed,
        // never UnsupportedAlgorithm. Important: the audit signal
        // must read "this token is not parseable" not "this
        // algorithm is not configured."
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        for none_variant in ["none", "None", "NONE", "nOnE"] {
            let header = serde_json::json!({ "alg": none_variant });
            let token = build_jwt(&header, &standard_payload(now_secs()));
            let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
                .await
                .unwrap_err();
            assert!(
                matches!(err, JwtVerificationError::Malformed),
                "alg={none_variant:?} -> {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_alg_string_returns_malformed() {
        // Unknown alg names (not in the IANA registered space) are
        // Malformed — not UnsupportedAlgorithm — because they're
        // either misformatted or alg-confusion attempts.
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let header = serde_json::json!({ "alg": "MyCustomAlg" });
        let token = build_jwt(&header, &standard_payload(now_secs()));
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::Malformed));
    }

    #[tokio::test]
    async fn known_alg_outside_allowlist_returns_unsupported_algorithm() {
        // ES256 is a known IANA alg name; if not in the operator's
        // configured allowlist (default: Ed25519-only) this is the
        // legitimate UnsupportedAlgorithm signal.
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let header = serde_json::json!({ "alg": "ES256" });
        let token = build_jwt(&header, &standard_payload(now_secs()));
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::UnsupportedAlgorithm(SignatureAlgorithm::Es256)));
    }

    // ============================================================
    // §7.2 signature verification tests.
    // ============================================================

    #[tokio::test]
    async fn happy_path_verifies_an_ed25519_signed_jwt() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let payload = standard_payload(now_secs());
        let token = build_jwt(&ed25519_header(), &payload);
        let v = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(v.issuer().as_str(), issuer_did().as_str());
        assert_eq!(v.algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(v.scope().scopes.as_slice(), &["tools.kryphocron.feed.read"]);
        assert!(v.nonce().is_none());
    }

    #[tokio::test]
    async fn tampered_payload_fails_signature_invalid() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let payload = standard_payload(now_secs());
        let token = build_jwt(&ed25519_header(), &payload);
        // Tamper the payload segment by re-encoding a different
        // payload while keeping the original signature.
        let mut parts = token.split('.');
        let header_b64 = parts.next().unwrap();
        let _orig_payload = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();
        let other_payload = serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": local_audience().service_did().as_str(),
            "iat": now_secs(),
            "exp": now_secs() + 600,
            "scope": "different.scope",
        });
        let other_payload_b64 = b64u(serde_json::to_vec(&other_payload).unwrap().as_slice());
        let tampered = format!("{header_b64}.{other_payload_b64}.{sig_b64}");
        let err = verify_jwt(&tampered, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::SignatureInvalid));
    }

    #[tokio::test]
    async fn tampered_signature_fails_signature_invalid() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        // Replace the signature with a same-length zero bitstring.
        let mut parts = token.rsplitn(2, '.');
        parts.next().unwrap(); // discard original sig
        let prefix = parts.next().unwrap();
        let zero_sig = b64u(&[0u8; ed25519_dalek::SIGNATURE_LENGTH]);
        let tampered = format!("{prefix}.{zero_sig}");
        let err = verify_jwt(&tampered, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::SignatureInvalid));
    }

    #[tokio::test]
    async fn wrong_key_fails_signature_invalid() {
        // Resolver returns the wrong public key for the issuer.
        let r = Arc::new(MockResolver::new());
        let wrong_key = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: SigningKey::from_bytes(&[99u8; 32]).verifying_key().to_bytes(),
        };
        r.insert(&issuer_did(), KeyId::from_bytes([1u8; 32]), wrong_key);
        let cfg = JwtVerificationConfig::default();
        let token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::SignatureInvalid));
    }

    // ============================================================
    // §7.2 claims verification tests.
    // ============================================================

    #[tokio::test]
    async fn expired_jwt_returns_expired_with_exp_and_now() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        // exp is 2 hours in the past, well outside skew.
        let now = now_secs();
        let payload = serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": local_audience().service_did().as_str(),
            "iat": now - 7200,
            "exp": now - 3600,
        });
        let token = build_jwt(&ed25519_header(), &payload);
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::Expired { .. }));
    }

    #[tokio::test]
    async fn future_dated_iat_returns_not_yet_valid() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        // iat is 5 minutes in the future, beyond skew.
        let now = now_secs();
        let payload = serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": local_audience().service_did().as_str(),
            "iat": now + 300,
            "exp": now + 600,
        });
        let token = build_jwt(&ed25519_header(), &payload);
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::NotYetValid { .. }));
    }

    #[tokio::test]
    async fn nbf_in_future_returns_not_yet_valid() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let now = now_secs();
        let payload = serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": local_audience().service_did().as_str(),
            "iat": now,
            "exp": now + 600,
            "nbf": now + 300,
        });
        let token = build_jwt(&ed25519_header(), &payload);
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::NotYetValid { .. }));
    }

    #[tokio::test]
    async fn wrong_audience_returns_wrong_audience() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let payload = serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": "did:web:somewhere.else",
            "iat": now_secs(),
            "exp": now_secs() + 600,
        });
        let token = build_jwt(&ed25519_header(), &payload);
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::WrongAudience { .. }));
    }

    #[tokio::test]
    async fn validity_window_too_long_returns_validity_window_too_long() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig {
            max_validity_window: Duration::from_secs(60),
            ..JwtVerificationConfig::default()
        };
        let now = now_secs();
        let payload = serde_json::json!({
            "iss": issuer_did().as_str(),
            "aud": local_audience().service_did().as_str(),
            "iat": now,
            "exp": now + 3600,
        });
        let token = build_jwt(&ed25519_header(), &payload);
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::ValidityWindowTooLong { .. }));
    }

    #[tokio::test]
    async fn issuer_resolution_failure_propagates() {
        let r = Arc::new(MockResolver::new());
        r.insert_err(&issuer_did(), DidResolutionError::NotFound);
        let cfg = JwtVerificationConfig::default();
        let token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::IssuerResolutionFailed(_)));
    }

    #[tokio::test]
    async fn issuer_key_not_in_document_when_document_empty() {
        let r = Arc::new(MockResolver::new());
        let empty_doc = DidDocument {
            did: issuer_did(),
            verification_methods: vec![],
            rotation_history: vec![],
            services: vec![],
            also_known_as: vec![],
            resolved_at: SystemTime::now(),
            resolver_cache_max_age: Duration::from_secs(3600),
        };
        r.documents.lock().unwrap().insert(issuer_did().as_str().to_string(), Ok(empty_doc));
        let cfg = JwtVerificationConfig::default();
        let token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::IssuerKeyNotInDocument));
    }

    // ============================================================
    // §7.2 nonce extraction tests.
    // ============================================================

    #[tokio::test]
    async fn require_nonce_true_with_missing_nonce_returns_nonce_missing() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig {
            require_nonce: true,
            ..JwtVerificationConfig::default()
        };
        let token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        let err = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::NonceMissing));
    }

    #[tokio::test]
    async fn require_nonce_false_with_present_nonce_succeeds() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let nonce_bytes = [0xABu8; 16];
        let mut payload = standard_payload(now_secs());
        payload["nonce"] = serde_json::Value::String(b64u(&nonce_bytes));
        let token = build_jwt(&ed25519_header(), &payload);
        let v = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(v.nonce().unwrap().as_bytes(), &nonce_bytes);
    }

    /// §7.2 commits `NonceReplay` as a variant. Phase 4a does not
    /// wire replay protection (the `NonceTracker` integration
    /// lands in Phase 4b); this test simply pins the variant
    /// exists and is constructible.
    #[test]
    fn nonce_replay_variant_is_reachable() {
        let _e = JwtVerificationError::NonceReplay;
    }

    // ============================================================
    // Scope-extraction tests.
    // ============================================================

    #[tokio::test]
    async fn scope_extracted_from_space_delimited_string() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let mut payload = standard_payload(now_secs());
        payload["scope"] = serde_json::Value::String("a.b c.d  e.f".into());
        let token = build_jwt(&ed25519_header(), &payload);
        let v = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(v.scope().scopes.as_slice(), &["a.b", "c.d", "e.f"]);
    }

    #[tokio::test]
    async fn scope_extracted_from_json_array() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let mut payload = standard_payload(now_secs());
        payload["scope"] = serde_json::json!(["x.y", "z.w"]);
        let token = build_jwt(&ed25519_header(), &payload);
        let v = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(v.scope().scopes.as_slice(), &["x.y", "z.w"]);
    }

    #[tokio::test]
    async fn scope_extracted_from_scp_field_name() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let mut payload = standard_payload(now_secs());
        payload.as_object_mut().unwrap().remove("scope");
        payload["scp"] = serde_json::Value::String("only.scope".into());
        let token = build_jwt(&ed25519_header(), &payload);
        let v = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(v.scope().scopes.as_slice(), &["only.scope"]);
    }

    #[tokio::test]
    async fn missing_scope_yields_empty_jwt_scope() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let mut payload = standard_payload(now_secs());
        payload.as_object_mut().unwrap().remove("scope");
        let token = build_jwt(&ed25519_header(), &payload);
        let v = verify_jwt(&token, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert!(v.scope().scopes.is_empty());
    }

    // ============================================================
    // Authorization-header parsing tests.
    // ============================================================

    #[tokio::test]
    async fn authorization_header_with_bearer_prefix_succeeds() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let raw_token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        let header_value = format!("Bearer {raw_token}");
        let v = verify_jwt(&header_value, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(v.issuer().as_str(), issuer_did().as_str());
    }

    #[tokio::test]
    async fn authorization_header_lowercase_bearer_also_succeeds() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let raw_token = build_jwt(&ed25519_header(), &standard_payload(now_secs()));
        let header_value = format!("bearer {raw_token}");
        let _v = verify_jwt(&header_value, &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_authorization_header_returns_malformed() {
        let r = populated_resolver();
        let cfg = JwtVerificationConfig::default();
        let err = verify_jwt("", &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::Malformed));
        let err = verify_jwt("Bearer ", &local_audience(), &*r, &cfg, deadline(), TraceId::from_bytes([0u8; 16]))
            .await
            .unwrap_err();
        assert!(matches!(err, JwtVerificationError::Malformed));
    }

    // ============================================================
    // §7.6 capability-claim verification tests.
    // ============================================================

    use crate::wire::{CapabilityClaim, ClaimNonce, DefaultNonceTracker, ResourceScope};
    use crate::authority::CapabilityKind;
    use crate::authority::subjects::ResourceId;

    fn issuer_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn issuer_service_identity() -> ServiceIdentity {
        let signing = issuer_signing_key();
        ServiceIdentity::new_internal(
            Did::new("did:plc:claimissuer").unwrap(),
            KeyId::from_bytes([0xAA; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: signing.verifying_key().to_bytes(),
            },
            None,
        )
    }

    fn audience_service_identity() -> ServiceIdentity {
        ServiceIdentity::new_internal(
            Did::new("did:web:audience.example").unwrap(),
            KeyId::from_bytes([0xBB; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn sample_resource_id() -> ResourceId {
        ResourceId::new(
            Did::new("did:plc:owner").unwrap(),
            crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            crate::Rkey::new("samplerkey").unwrap(),
        )
    }

    fn build_claim() -> CapabilityClaim {
        CapabilityClaim::new(
            issuer_service_identity(),
            audience_service_identity(),
            Did::new("did:plc:subject").unwrap(),
            vec![CapabilityKind::ViewPrivate],
            ResourceScope::Resource(sample_resource_id()),
            ClaimNonce::from_bytes([0xCC; 16]),
            TraceId::from_bytes([0xDD; 16]),
            Duration::from_secs(60),
            &issuer_signing_key(),
        )
        .unwrap()
    }

    fn populated_claim_resolver() -> Arc<MockResolver> {
        let resolver = Arc::new(MockResolver::new());
        let issuer = issuer_service_identity();
        resolver.insert(
            issuer.service_did(),
            issuer.key_id(),
            *issuer.key_material(),
        );
        resolver
    }

    fn b64u_wire(claim: &CapabilityClaim) -> String {
        URL_SAFE_NO_PAD.encode(claim.to_wire_bytes())
    }

    /// §7.6 default-config commitments.
    #[test]
    fn claim_config_default_is_ed25519_only() {
        let c = ClaimVerificationConfig::default();
        assert_eq!(c.accepted_algorithms, &[SignatureAlgorithm::Ed25519]);
        assert_eq!(c.max_clock_skew, Duration::from_secs(30));
        assert_eq!(c.max_validity_window, Duration::from_secs(600));
    }

    #[tokio::test]
    async fn claim_happy_path_verifies_an_ed25519_signed_claim() {
        let claim = build_claim();
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let header = format!("KryphocronClaim {}", b64u_wire(&claim));
        let v = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap();
        assert_eq!(v.issuer().service_did().as_str(), "did:plc:claimissuer");
        assert_eq!(v.subject().as_str(), "did:plc:subject");
        assert_eq!(v.capabilities(), &[CapabilityKind::ViewPrivate]);
    }

    #[tokio::test]
    async fn claim_replay_against_same_nonce_returns_nonce_replay() {
        let claim = build_claim();
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let header = format!("KryphocronClaim {}", b64u_wire(&claim));
        // First verification succeeds.
        let _v = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap();
        // Second verification of the same wire bytes (same nonce
        // under the same issuer partition) is rejected.
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::NonceReplay));
    }

    #[tokio::test]
    async fn claim_wrong_audience_returns_wrong_audience_with_did() {
        let claim = build_claim();
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let header = format!("KryphocronClaim {}", b64u_wire(&claim));
        // Verify against a different audience identity.
        let other_audience = ServiceIdentity::new_internal(
            Did::new("did:web:somewhere.else").unwrap(),
            KeyId::from_bytes([0; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0; 32],
            },
            None,
        );
        let err = verify_capability_claim(
            &header,
            &other_audience,
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        match err {
            ClaimVerificationError::WrongAudience { got, .. } => {
                // Phase 4a note: `got` is a Did, not a
                // synthetic ServiceIdentity placeholder.
                assert_eq!(got.as_str(), "did:web:audience.example");
            }
            other => panic!("expected WrongAudience, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn claim_with_invalid_base64url_returns_malformed() {
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let err = verify_capability_claim(
            "KryphocronClaim ***not-base64url***",
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::Malformed));
    }

    #[tokio::test]
    async fn claim_with_non_canonical_cbor_returns_malformed() {
        // Hand-built CBOR map with non-canonical key ordering
        // (`zebra` before `apple`). Decodes successfully via
        // ciborium but fails the round-trip canonicality check.
        let non_canonical: Vec<u8> = vec![
            0xA2, 0x65, 0x7A, 0x65, 0x62, 0x72, 0x61, 0x01, 0x65, 0x61, 0x70, 0x70,
            0x6C, 0x65, 0x02,
        ];
        let header = format!("KryphocronClaim {}", URL_SAFE_NO_PAD.encode(&non_canonical));
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::Malformed));
    }

    #[tokio::test]
    async fn claim_too_large_returns_claim_too_large() {
        // A wire-bytes payload larger than MAX_CAPABILITY_CLAIM_SIZE.
        // Construct via raw bytes (not via CapabilityClaim::new
        // which would itself reject at construction).
        let oversized = vec![0u8; MAX_CAPABILITY_CLAIM_SIZE + 1];
        let header = format!("KryphocronClaim {}", URL_SAFE_NO_PAD.encode(&oversized));
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::ClaimTooLarge { .. }));
    }

    #[tokio::test]
    async fn claim_tampered_signature_fails_signature_invalid() {
        // Tamper the signature bytes specifically. Decoding the
        // wire envelope still succeeds (signature shape is the
        // same 64 bytes); the signature verification step fails
        // unambiguously with SignatureInvalid.
        let claim = build_claim();
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let wire = claim.to_wire_bytes();
        // The 64 signature bytes are the last 64 bytes of the
        // payload byte string in the canonical-CBOR encoding —
        // ciborium's `bytes(64)` head is `0x58 0x40` followed by
        // 64 raw bytes. Find the byte-string head and zero its
        // payload.
        let mut tampered = wire.clone();
        let head_pos = tampered
            .windows(2)
            .position(|w| w == [0x58, 0x40])
            .expect("wire envelope must contain a bytes(64) for the signature");
        let sig_start = head_pos + 2;
        for b in &mut tampered[sig_start..sig_start + 64] {
            *b = 0;
        }
        let header = format!("KryphocronClaim {}", URL_SAFE_NO_PAD.encode(&tampered));
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::SignatureInvalid));
    }

    /// §4.8 W8 domain-separation: a signature computed WITHOUT
    /// the `CLAIM_DOMAIN_TAG` prefix (e.g., the same canonical
    /// payload signed JWT-style with a bare-bytes signing input)
    /// must NOT verify. Otherwise an attacker who captures a
    /// signature in one domain (delegation receipt, JWT, etc.)
    /// could replay it in the capability-claim domain — exactly
    /// the cross-domain confusion W8 forecloses.
    #[tokio::test]
    async fn claim_signature_without_domain_tag_fails_verification() {
        use ed25519_dalek::Signer;

        let claim = build_claim();
        let canonical_payload = claim.canonical_payload_bytes();
        // Sign the bare canonical payload — *without* prepending
        // CLAIM_DOMAIN_TAG. This is the cross-domain forgery
        // attempt.
        let bare_sig = issuer_signing_key().sign(&canonical_payload);
        let forged_signature = crate::wire::ClaimSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: bare_sig.to_bytes(),
        };
        let forged_claim = crate::wire::CapabilityClaim::new_internal_received(
            issuer_service_identity(),
            audience_service_identity(),
            Did::new("did:plc:subject").unwrap(),
            crate::wire::ClaimOrigin::SelfOriginated,
            vec![CapabilityKind::ViewPrivate],
            crate::wire::ResourceScope::Resource(sample_resource_id()),
            ClaimNonce::from_bytes([0xCC; 16]),
            TraceId::from_bytes([0xDD; 16]),
            claim.issued_at(),
            claim.expires_at(),
            forged_signature,
        );
        let header = format!("KryphocronClaim {}", URL_SAFE_NO_PAD.encode(forged_claim.to_wire_bytes()));
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ClaimVerificationError::SignatureInvalid),
            "domain-separation bypass must fail; got {err:?}"
        );
    }

    /// §4.8 W6 belt-and-suspenders at receive: an externally-
    /// minted claim carrying a substrate-class capability must
    /// be rejected at receive even though `CapabilityClaim::new`
    /// would have caught it at construction. The substrate's own
    /// claims pass W6 at issuance; external claims may not.
    #[tokio::test]
    async fn claim_with_substrate_capability_returns_non_wire_eligible_at_receive() {
        use ed25519_dalek::Signer;

        // Build a wire envelope by hand: bypass the
        // construction-time W6 check via the crate-internal
        // received-shape constructor, then properly sign with
        // domain separation.
        let issuer = issuer_service_identity();
        let bad_caps = vec![CapabilityKind::ScanShard]; // substrate-class
        let issued_at = SystemTime::now();
        let expires_at = issued_at + Duration::from_secs(60);
        let nonce = ClaimNonce::from_bytes([0xEE; 16]);
        let trace = TraceId::from_bytes([0xFF; 16]);
        // Provisional claim with a placeholder signature so we
        // can call canonical_payload_bytes(); the signature isn't
        // included in the canonical payload anyway.
        let placeholder_sig = crate::wire::ClaimSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: [0; 64],
        };
        let provisional = crate::wire::CapabilityClaim::new_internal_received(
            issuer.clone(),
            audience_service_identity(),
            Did::new("did:plc:subject").unwrap(),
            crate::wire::ClaimOrigin::SelfOriginated,
            bad_caps.clone(),
            crate::wire::ResourceScope::ClassWideAdministrative,
            nonce,
            trace,
            issued_at,
            expires_at,
            placeholder_sig,
        );
        let canonical_payload = provisional.canonical_payload_bytes();
        let mut signing_input = Vec::new();
        signing_input.extend_from_slice(crate::wire::CLAIM_DOMAIN_TAG);
        signing_input.extend_from_slice(&canonical_payload);
        let real_sig = issuer_signing_key().sign(&signing_input);
        let signed = crate::wire::CapabilityClaim::new_internal_received(
            issuer,
            audience_service_identity(),
            Did::new("did:plc:subject").unwrap(),
            crate::wire::ClaimOrigin::SelfOriginated,
            bad_caps,
            crate::wire::ResourceScope::ClassWideAdministrative,
            nonce,
            trace,
            issued_at,
            expires_at,
            crate::wire::ClaimSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: real_sig.to_bytes(),
            },
        );
        let header = format!(
            "KryphocronClaim {}",
            URL_SAFE_NO_PAD.encode(signed.to_wire_bytes())
        );
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ClaimVerificationError::NonWireEligibleCapability(CapabilityKind::ScanShard)
        ));
    }

    #[tokio::test]
    async fn claim_with_known_alg_outside_allowlist_returns_unsupported_algorithm() {
        let claim = build_claim();
        let resolver = populated_claim_resolver();
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig {
            accepted_algorithms: &[],
            ..ClaimVerificationConfig::default()
        };
        let header = format!("KryphocronClaim {}", b64u_wire(&claim));
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*resolver,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ClaimVerificationError::UnsupportedAlgorithm(SignatureAlgorithm::Ed25519)
        ));
    }

    /// §4.8 W12 (Phase 4c): a claim signed by a
    /// key that has been rotated out — present in the resolver's
    /// `rotation_history`, absent from `verification_methods` —
    /// still verifies. Phase 4b's exact-match-only logic would
    /// have rejected with `IssuerKeyNotInDocument` here.
    #[tokio::test]
    async fn claim_signed_by_rotated_out_key_still_verifies_via_rotation_history() {
        let claim = build_claim();
        let issuer = issuer_service_identity();
        // Build a resolver document where the issuer's current
        // key is a *different* one (rotated in), but the claim's
        // actual signing key is in rotation_history.
        let r = Arc::new(MockResolver::new());
        let rotated_in_key = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let rotated_in_pub = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: rotated_in_key.verifying_key().to_bytes(),
        };
        let mut doc = crate::resolver::DidDocument {
            did: issuer.service_did().clone(),
            verification_methods: vec![(KeyId::from_bytes([0xFF; 32]), rotated_in_pub)],
            rotation_history: vec![(issuer.key_id(), *issuer.key_material())],
            services: vec![],
            also_known_as: vec![],
            resolved_at: SystemTime::now(),
            resolver_cache_max_age: Duration::from_secs(3600),
        };
        // Also keep the rotation-history field's KeyId aligned
        // with the claim issuer's KeyId so the lookup matches.
        doc.rotation_history = vec![(issuer.key_id(), *issuer.key_material())];
        r.documents
            .lock()
            .unwrap()
            .insert(issuer.service_did().as_str().to_string(), Ok(doc));

        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let header = format!("KryphocronClaim {}", b64u_wire(&claim));
        let v = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*r,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap();
        assert_eq!(v.issuer().service_did().as_str(), "did:plc:claimissuer");
    }

    /// Negative: a claim signed by a key whose KeyId is NOT in
    /// verification_methods OR rotation_history fails with
    /// `IssuerKeyNotInDocument`. Pins that the rotation walk
    /// doesn't accept arbitrary keys (the lookup is by KeyId,
    /// not by bytewise key-material comparison).
    #[tokio::test]
    async fn claim_signed_by_unknown_key_returns_issuer_key_not_in_document() {
        let claim = build_claim();
        let issuer = issuer_service_identity();
        // The claim's `issuer.key_id()` is [0xAA; 32]
        // (per `issuer_service_identity()`). Build a document
        // whose KeyIds don't include [0xAA; 32].
        let r = Arc::new(MockResolver::new());
        let unrelated_key = ed25519_dalek::SigningKey::from_bytes(&[123u8; 32]);
        let unrelated_pub = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: unrelated_key.verifying_key().to_bytes(),
        };
        let doc = crate::resolver::DidDocument {
            did: issuer.service_did().clone(),
            verification_methods: vec![(KeyId::from_bytes([0x11; 32]), unrelated_pub)],
            rotation_history: vec![(KeyId::from_bytes([0x22; 32]), unrelated_pub)],
            services: vec![],
            also_known_as: vec![],
            resolved_at: SystemTime::now(),
            resolver_cache_max_age: Duration::from_secs(3600),
        };
        r.documents
            .lock()
            .unwrap()
            .insert(issuer.service_did().as_str().to_string(), Ok(doc));
        let tracker = DefaultNonceTracker::new();
        let cfg = ClaimVerificationConfig::default();
        let header = format!("KryphocronClaim {}", b64u_wire(&claim));
        let err = verify_capability_claim(
            &header,
            &audience_service_identity(),
            &*r,
            &tracker,
            &cfg,
            deadline(),
            TraceId::from_bytes([0u8; 16]),
            &CapabilitySet::empty(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::IssuerKeyNotInDocument));
    }

    // ============================================================
    // §7.5 — handshake verifier smoke tests.
    // ============================================================

    fn handshake_signing_pair(seed: u8) -> (SigningKey, PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        (
            sk,
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: vk.to_bytes(),
            },
        )
    }

    fn make_initiator_identity(seed: u8) -> (ServiceIdentity, SigningKey) {
        let (sk, pk) = handshake_signing_pair(seed);
        let did_str = format!("did:plc:{seed:02x}initiator0000000");
        let did = Did::new(&did_str).unwrap();
        let key_id = KeyId::from_bytes([seed; 32]);
        let id = ServiceIdentity::new_internal(did, key_id, pk, None);
        (id, sk)
    }

    fn handshake_test_resolver(initiator: &ServiceIdentity) -> Arc<MockResolver> {
        let r = Arc::new(MockResolver::new());
        r.insert(initiator.service_did(), initiator.key_id(), *initiator.key_material());
        r
    }

    /// §7.5 happy path: verify_sync_hello accepts a freshly-signed
    /// Hello and yields a sealed [`VerifiedSyncHello`].
    #[tokio::test]
    async fn verify_sync_hello_happy_path() {
        let (initiator, sk) = make_initiator_identity(0x10);
        let resolver = handshake_test_resolver(&initiator);
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();

        let nonce = SessionNonce::from_bytes([0x42; 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Bidirectional,
        };
        let at = SystemTime::now();
        let sign_input = crate::wire::hello_sign_input(
            &initiator,
            SemVer::new(1, 0, 0),
            &nonce,
            &scope,
            at,
        );
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let hello = SyncChannelHello {
            initiator_identity: initiator.clone(),
            initiator_lexicon_set_version: SemVer::new(1, 0, 0),
            proposed_session_nonce: nonce,
            requested_scope: scope.clone(),
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);

        let v = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0xAB; 16]),
        )
        .await
        .unwrap();
        assert_eq!(v.initiator_identity(), &initiator);
        assert_eq!(v.proposed_session_nonce(), &nonce);
    }

    /// §7.5 nonce-replay path: a second verify_sync_hello call
    /// with the same nonce surfaces HandshakeNonceReplay carrying
    /// the recorded first_seen_at.
    #[tokio::test]
    async fn verify_sync_hello_replay_returns_handshake_nonce_replay() {
        let (initiator, sk) = make_initiator_identity(0x11);
        let resolver = handshake_test_resolver(&initiator);
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();

        let nonce = SessionNonce::from_bytes([0x43; 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Receive,
        };
        let at = SystemTime::now();
        let sign_input = crate::wire::hello_sign_input(
            &initiator,
            SemVer::new(1, 0, 0),
            &nonce,
            &scope,
            at,
        );
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let hello = SyncChannelHello {
            initiator_identity: initiator.clone(),
            initiator_lexicon_set_version: SemVer::new(1, 0, 0),
            proposed_session_nonce: nonce,
            requested_scope: scope,
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);

        verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0xAB; 16]),
        )
        .await
        .unwrap();

        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0xAB; 16]),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SyncHandshakeVerificationError::HandshakeNonceReplay { .. }),
            "expected HandshakeNonceReplay, got {err:?}"
        );
    }

    /// §7.5 / §5.5 major-version skew: an initiator newer than the
    /// responder by a major version surfaces
    /// LexiconSetMajorVersionMismatch.
    #[tokio::test]
    async fn verify_sync_hello_rejects_major_version_skew() {
        let (initiator, sk) = make_initiator_identity(0x12);
        let resolver = handshake_test_resolver(&initiator);
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig {
            local_lexicon_set_version: SemVer::new(1, 0, 0),
            ..SyncHandshakeVerificationConfig::default()
        };

        let initiator_ver = SemVer::new(2, 0, 0);
        let nonce = SessionNonce::from_bytes([0x44; 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Send,
        };
        let at = SystemTime::now();
        let sign_input = crate::wire::hello_sign_input(
            &initiator, initiator_ver, &nonce, &scope, at,
        );
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let hello = SyncChannelHello {
            initiator_identity: initiator,
            initiator_lexicon_set_version: initiator_ver,
            proposed_session_nonce: nonce,
            requested_scope: scope,
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);

        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0xAB; 16]),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SyncHandshakeVerificationError::LexiconSetMajorVersionMismatch { .. }
            ),
            "expected LexiconSetMajorVersionMismatch, got {err:?}"
        );
    }

    /// §7.5 W8: an Established message signed by an initiator
    /// against a different responder identity than the one verifying
    /// fails signature verification (the responder identity is
    /// covered by the signature implicitly via the sign-input).
    #[test]
    fn verify_sync_established_fails_against_wrong_responder() {
        let (sk, init_pk) = handshake_signing_pair(0x20);
        let local_id_a = ServiceIdentity::new_internal(
            Did::new("did:plc:respondera000000000000").unwrap(),
            KeyId::from_bytes([0x21; 32]),
            init_pk,
            None,
        );
        let local_id_b = ServiceIdentity::new_internal(
            Did::new("did:plc:responderb000000000000").unwrap(),
            KeyId::from_bytes([0x22; 32]),
            init_pk,
            None,
        );
        let session_id = SessionId::from_bytes([0xCC; 32]);
        let at = SystemTime::now();

        // Initiator signs Established for responder A.
        let sign_input =
            crate::wire::established_sign_input(&session_id, &local_id_a, at);
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let est = SyncChannelEstablished {
            session_id,
            initiator_signature: sig,
            at,
        };
        let bytes = established_to_wire_bytes(&est);
        let cfg = SyncHandshakeVerificationConfig::default();

        // Responder B tries to verify (wrong responder context):
        // sign-input differs because local_identity differs.
        let err = verify_sync_established(&bytes, &local_id_b, &init_pk, &cfg)
            .unwrap_err();
        assert!(matches!(err, SyncHandshakeVerificationError::SignatureInvalid));

        // Responder A succeeds.
        let v = verify_sync_established(&bytes, &local_id_a, &init_pk, &cfg).unwrap();
        assert_eq!(v.session_id(), session_id);
    }

    // ============================================================
    // §7.5 — VerifiedSyncHello scope accessor split.
    // ============================================================

    fn fresh_verified_sync_hello(time_window: Option<crate::wire::SyncTimeWindow>) -> VerifiedSyncHello {
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window,
            direction: crate::wire::SyncDirection::Bidirectional,
        };
        VerifiedSyncHello::new_internal(
            ServiceIdentity::new_internal(
                Did::new("did:plc:initiator00000000000000").unwrap(),
                KeyId::from_bytes([0x10; 32]),
                PublicKey {
                    algorithm: SignatureAlgorithm::Ed25519,
                    bytes: [0x11; 32],
                },
                None,
            ),
            SemVer::new(1, 0, 0),
            SessionNonce::from_bytes([0x42; 32]),
            scope,
            SystemTime::now(),
        )
    }

    /// `PeerKind::Internal` is exempt from the §7.5 default
    /// federation narrowing — even with `time_window: None`, the
    /// scope is returned unchanged.
    #[test]
    fn narrowed_scope_internal_peer_unchanged_even_for_none_window() {
        let v = fresh_verified_sync_hello(None);
        let now = SystemTime::now();
        let narrowed = v.narrowed_scope(crate::resolver::PeerKind::Internal, None, now);
        assert!(narrowed.time_window.is_none());
    }

    /// `PeerKind::Federation` + `time_window: None` → narrowed to
    /// the §7.5 default 7-day window ending `now`.
    #[test]
    fn narrowed_scope_federation_peer_with_none_window_narrows_to_7_days() {
        let v = fresh_verified_sync_hello(None);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let narrowed = v.narrowed_scope(crate::resolver::PeerKind::Federation, None, now);
        let window = narrowed.time_window.expect("federation None must narrow");
        assert_eq!(window.end, now);
        assert_eq!(
            window.start,
            now - crate::wire::DEFAULT_FEDERATION_TIME_WINDOW
        );
    }

    /// `PeerKind::Federation` + already-bounded `time_window` →
    /// returned unchanged (the initiator already supplied a
    /// bound; the default-narrowing rule applies only when the
    /// initiator left it open).
    #[test]
    fn narrowed_scope_federation_peer_with_bounded_window_unchanged() {
        let initiator_window = crate::wire::SyncTimeWindow {
            start: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            end: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        };
        let v = fresh_verified_sync_hello(Some(initiator_window));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_001);
        let narrowed = v.narrowed_scope(crate::resolver::PeerKind::Federation, None, now);
        assert_eq!(narrowed.time_window, Some(initiator_window));
    }

    /// `requested_scope` returns the unmodified initiator-requested
    /// scope regardless of peer kind. (The accessor split's whole
    /// point is that this is for audit logging only.)
    #[test]
    fn requested_scope_returns_raw_initiator_scope() {
        let v = fresh_verified_sync_hello(None);
        assert!(v.requested_scope().time_window.is_none());
    }

    // ============================================================
    // §4.8 W11 / W12 / W13 — chain verification tests.
    // ============================================================

    use crate::wire::{sign_delegation_receipt, DelegationReceipt};

    fn chain_test_pair(seed: u8) -> (SigningKey, PublicKey, KeyId, Did) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let pk = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: vk.to_bytes(),
        };
        let key_id = KeyId::from_bytes([seed; 32]);
        let did_str = format!("did:plc:{seed:02x}principal000000");
        let did = Did::new(&did_str).unwrap();
        (sk, pk, key_id, did)
    }

    fn chain_test_resolver_for(pairs: &[(Did, KeyId, PublicKey)]) -> Arc<MockResolver> {
        let r = Arc::new(MockResolver::new());
        for (did, key_id, key) in pairs {
            r.insert(did, *key_id, *key);
        }
        r
    }

    fn build_signed_entry(
        previous_did: &Did,
        previous_key_id: KeyId,
        previous_signing_key: &SigningKey,
        recipient_did: &Did,
        recipient_key_id: KeyId,
        recipient_pk: PublicKey,
        granted: CapabilitySet,
    ) -> AttributionEntryWire {
        let derived_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let payload = DelegationReceiptPayload {
            previous_principal_did: previous_did.clone(),
            previous_key_id,
            recipient_principal_did: recipient_did.clone(),
            recipient_key_id,
            derivation_reason: crate::ingress::DerivationReason::DropPrivilegeToAnonymous,
            granted_capabilities: granted.clone(),
            derived_at,
        };
        let receipt = sign_delegation_receipt(&payload, previous_signing_key);
        AttributionEntryWire {
            principal: AttributionPrincipal::Service(
                ServiceIdentity::new_internal(
                    recipient_did.clone(),
                    recipient_key_id,
                    recipient_pk,
                    None,
                ),
            ),
            derivation_reason: crate::ingress::DerivationReason::DropPrivilegeToAnonymous,
            derived_at,
            granted_capabilities: granted,
            receipt,
        }
    }

    /// §4.8 W11/W12/W13 happy path: a single-hop chain with valid
    /// receipt and monotonic capabilities verifies.
    #[tokio::test]
    async fn verify_attribution_chain_happy_path_single_hop() {
        let (sk_a, pk_a, kid_a, did_a) = chain_test_pair(0xA0);
        let (_sk_b, pk_b, kid_b, did_b) = chain_test_pair(0xB0);
        let resolver = chain_test_resolver_for(&[(did_a.clone(), kid_a, pk_a)]);
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        let entry = build_signed_entry(
            &did_a, kid_a, &sk_a,
            &did_b, kid_b, pk_b,
            origin_caps.clone(),
        );
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(),
                kid_a,
                pk_a,
                None,
            )),
            entries: smallvec::smallvec![entry],
        };

        let verified = verify_attribution_chain(
            &chain,
            &origin_caps,
            resolver.as_ref() as &dyn DidResolver,
            deadline(),
            TraceId::from_bytes([0xCD; 16]),
        )
        .await
        .unwrap();
        assert_eq!(verified.entries().len(), 1);
    }

    /// §4.8 W13 capability-laundering probe: a hop attempting to
    /// grant a capability the previous hop did not authorize fails
    /// with `CapabilityExpansion { hop, attempted, available }`.
    #[tokio::test]
    async fn verify_attribution_chain_w13_capability_expansion_fails_closed() {
        let (sk_a, pk_a, kid_a, did_a) = chain_test_pair(0xA1);
        let (_sk_b, pk_b, kid_b, did_b) = chain_test_pair(0xB1);
        let resolver = chain_test_resolver_for(&[(did_a.clone(), kid_a, pk_a)]);

        // Origin authorized: only CreateRecord.
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        // Hop 0 attempts CreateRecord + DeleteRecord → expansion.
        let attempted = CapabilitySet::from_kinds(vec![
            CapabilityKind::ViewPrivate,
            CapabilityKind::EditPrivatePost,
        ]);
        let entry = build_signed_entry(
            &did_a, kid_a, &sk_a,
            &did_b, kid_b, pk_b,
            attempted,
        );
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(),
                kid_a,
                pk_a,
                None,
            )),
            entries: smallvec::smallvec![entry],
        };

        let err = verify_attribution_chain(
            &chain,
            &origin_caps,
            resolver.as_ref() as &dyn DidResolver,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        match err {
            BindError::AttributionReceiptInvalid {
                failing_hop,
                reason: ReceiptVerificationFailure::CapabilityExpansion { hop, .. },
            } => {
                assert_eq!(failing_hop, 0);
                assert_eq!(hop, 0);
            }
            other => panic!("expected CapabilityExpansion at hop 0, got {other:?}"),
        }
    }

    /// §4.8 W12 SignatureInvalid: a hop whose receipt was signed
    /// by a different key than the previous principal's resolved
    /// key fails with `SignatureInvalid`.
    #[tokio::test]
    async fn verify_attribution_chain_signature_invalid() {
        let (sk_a, pk_a, kid_a, did_a) = chain_test_pair(0xA2);
        let (sk_imposter, _, _, _) = chain_test_pair(0xC2);
        let (_sk_b, pk_b, kid_b, did_b) = chain_test_pair(0xB2);
        // Resolver returns A's real public key; receipt was signed
        // by an imposter signing key → SignatureInvalid (no key in
        // A's rotation history matches).
        let resolver = chain_test_resolver_for(&[(did_a.clone(), kid_a, pk_a)]);
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        let entry = build_signed_entry(
            &did_a, kid_a, &sk_imposter,
            &did_b, kid_b, pk_b,
            origin_caps.clone(),
        );
        // Suppress the unused-warning for sk_a — sk_a is what
        // would have signed legitimately; we use sk_imposter.
        let _ = &sk_a;
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(), kid_a, pk_a, None,
            )),
            entries: smallvec::smallvec![entry],
        };

        let err = verify_attribution_chain(
            &chain, &origin_caps,
            resolver.as_ref() as &dyn DidResolver,
            deadline(), TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            BindError::AttributionReceiptInvalid {
                reason: ReceiptVerificationFailure::SignatureInvalid,
                ..
            }
        ));
    }

    /// §4.8 W12 KeyNotInRotationHistory: previous principal's
    /// resolved DID document carries no Ed25519 key (only Es256).
    #[tokio::test]
    async fn verify_attribution_chain_key_not_in_rotation_history() {
        let (sk_a, _pk_a, kid_a, did_a) = chain_test_pair(0xA3);
        // Resolved doc has an Es256 key, not Ed25519. Receipt
        // claims Ed25519 algorithm.
        let pk_a_es256 = PublicKey {
            algorithm: SignatureAlgorithm::Es256,
            bytes: [0x33; 32],
        };
        let (_sk_b, pk_b, kid_b, did_b) = chain_test_pair(0xB3);
        let resolver = chain_test_resolver_for(&[(did_a.clone(), kid_a, pk_a_es256)]);
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        let entry = build_signed_entry(
            &did_a, kid_a, &sk_a,
            &did_b, kid_b, pk_b,
            origin_caps.clone(),
        );
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(), kid_a, pk_a_es256, None,
            )),
            entries: smallvec::smallvec![entry],
        };

        let err = verify_attribution_chain(
            &chain, &origin_caps,
            resolver.as_ref() as &dyn DidResolver,
            deadline(), TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            BindError::AttributionReceiptInvalid {
                reason: ReceiptVerificationFailure::KeyNotInRotationHistory { .. },
                ..
            }
        ));
    }

    /// §4.8 W12 PreviousPrincipalUnresolvable: resolver returns
    /// NotFound for the previous principal's DID.
    #[tokio::test]
    async fn verify_attribution_chain_previous_principal_unresolvable() {
        let (sk_a, pk_a, kid_a, did_a) = chain_test_pair(0xA4);
        let (_sk_b, pk_b, kid_b, did_b) = chain_test_pair(0xB4);
        // Resolver insert_err for the previous principal.
        let r = Arc::new(MockResolver::new());
        r.insert_err(&did_a, DidResolutionError::NotFound);
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        let entry = build_signed_entry(
            &did_a, kid_a, &sk_a,
            &did_b, kid_b, pk_b,
            origin_caps.clone(),
        );
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(), kid_a, pk_a, None,
            )),
            entries: smallvec::smallvec![entry],
        };

        let err = verify_attribution_chain(
            &chain, &origin_caps,
            r.as_ref() as &dyn DidResolver,
            deadline(), TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            BindError::AttributionReceiptInvalid {
                reason: ReceiptVerificationFailure::PreviousPrincipalUnresolvable(_),
                ..
            }
        ));
    }

    /// §4.8 W12 AlgorithmNotAccepted: receipt's algorithm is
    /// outside the verifier's allowlist (Ed25519 only in v1).
    #[tokio::test]
    async fn verify_attribution_chain_algorithm_not_accepted() {
        let (sk_a, pk_a, kid_a, did_a) = chain_test_pair(0xA5);
        let (_sk_b, pk_b, kid_b, did_b) = chain_test_pair(0xB5);
        let resolver = chain_test_resolver_for(&[(did_a.clone(), kid_a, pk_a)]);
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        let mut entry = build_signed_entry(
            &did_a, kid_a, &sk_a,
            &did_b, kid_b, pk_b,
            origin_caps.clone(),
        );
        // Stamp the receipt's algorithm to Es256 so the allowlist
        // check fires before signature verification.
        entry.receipt = DelegationReceipt {
            algorithm: SignatureAlgorithm::Es256,
            bytes: entry.receipt.bytes,
        };
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(), kid_a, pk_a, None,
            )),
            entries: smallvec::smallvec![entry],
        };

        let err = verify_attribution_chain(
            &chain, &origin_caps,
            resolver.as_ref() as &dyn DidResolver,
            deadline(), TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            BindError::AttributionReceiptInvalid {
                reason: ReceiptVerificationFailure::AlgorithmNotAccepted(SignatureAlgorithm::Es256),
                ..
            }
        ));
    }

    /// §4.8 chain depth bound: chain with > MAX_CHAIN_DEPTH entries
    /// fails as Malformed before any per-hop work runs.
    #[tokio::test]
    async fn verify_attribution_chain_over_depth_returns_malformed() {
        let (sk_a, pk_a, kid_a, did_a) = chain_test_pair(0xA6);
        let (_, pk_b, kid_b, did_b) = chain_test_pair(0xB6);
        let resolver = chain_test_resolver_for(&[(did_a.clone(), kid_a, pk_a)]);
        let origin_caps = CapabilitySet::from_kinds(vec![CapabilityKind::ViewPrivate]);

        let entry = build_signed_entry(
            &did_a, kid_a, &sk_a,
            &did_b, kid_b, pk_b,
            origin_caps.clone(),
        );
        // Build MAX_CHAIN_DEPTH + 1 entries — over the cap.
        let mut entries: smallvec::SmallVec<[AttributionEntryWire; 8]> =
            smallvec::SmallVec::new();
        for _ in 0..(crate::ingress::MAX_CHAIN_DEPTH + 1) {
            entries.push(entry.clone());
        }
        let chain = AttributionChainWire {
            origin: AttributionPrincipal::Service(ServiceIdentity::new_internal(
                did_a.clone(), kid_a, pk_a, None,
            )),
            entries,
        };

        let err = verify_attribution_chain(
            &chain, &origin_caps,
            resolver.as_ref() as &dyn DidResolver,
            deadline(), TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            BindError::AttributionReceiptInvalid {
                reason: ReceiptVerificationFailure::Malformed,
                ..
            }
        ));
    }

    // ============================================================
    // §7.5 — SyncHandshakeVerificationError
    // variant test coverage round-out.
    // ============================================================

    /// Builds a valid signed Hello, returning the wire bytes plus
    /// the initiator's identity / signing key for tests that
    /// tweak fields after-the-fact.
    fn build_valid_hello(
        seed: u8,
    ) -> (Vec<u8>, ServiceIdentity, SigningKey) {
        let (initiator, sk) = make_initiator_identity(seed);
        let nonce = SessionNonce::from_bytes([seed.wrapping_mul(3); 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Bidirectional,
        };
        let at = SystemTime::now();
        let sign_input = crate::wire::hello_sign_input(
            &initiator,
            SemVer::new(1, 0, 0),
            &nonce,
            &scope,
            at,
        );
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let hello = SyncChannelHello {
            initiator_identity: initiator.clone(),
            initiator_lexicon_set_version: SemVer::new(1, 0, 0),
            proposed_session_nonce: nonce,
            requested_scope: scope,
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);
        (bytes, initiator, sk)
    }

    /// Malformed: garbage bytes that don't parse as canonical CBOR.
    #[tokio::test]
    async fn verify_sync_hello_returns_malformed_for_garbage_bytes() {
        let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let resolver = Arc::new(MockResolver::new());
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SyncHandshakeVerificationError::Malformed));
    }

    /// TooLarge: payload exceeds MAX_HANDSHAKE_MESSAGE_SIZE.
    #[tokio::test]
    async fn verify_sync_hello_returns_too_large_above_size_ceiling() {
        let bytes = vec![0u8; crate::wire::MAX_HANDSHAKE_MESSAGE_SIZE + 1];
        let resolver = Arc::new(MockResolver::new());
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SyncHandshakeVerificationError::TooLarge));
    }

    /// CounterpartyResolutionFailed: resolver returns NotFound for
    /// the initiator's DID.
    #[tokio::test]
    async fn verify_sync_hello_returns_counterparty_resolution_failed() {
        let (bytes, initiator, _sk) = build_valid_hello(0x30);
        let resolver = Arc::new(MockResolver::new());
        resolver.insert_err(initiator.service_did(), DidResolutionError::NotFound);
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SyncHandshakeVerificationError::CounterpartyResolutionFailed(_)
        ));
    }

    /// CounterpartyKeyNotInDocument: resolver returns a document
    /// without the named key.
    #[tokio::test]
    async fn verify_sync_hello_returns_counterparty_key_not_in_document() {
        let (bytes, initiator, _sk) = build_valid_hello(0x31);
        let resolver = Arc::new(MockResolver::new());
        // Insert a document with a DIFFERENT KeyId than the
        // initiator's claimed identity references.
        let other_kid = KeyId::from_bytes([0x99; 32]);
        resolver.insert(initiator.service_did(), other_kid, *initiator.key_material());
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SyncHandshakeVerificationError::CounterpartyKeyNotInDocument
        ));
    }

    /// UnsupportedAlgorithm: receipt's algorithm is outside the
    /// allowlist (Ed25519 only by default).
    #[tokio::test]
    async fn verify_sync_hello_returns_unsupported_algorithm() {
        let (bytes, initiator, _sk) = build_valid_hello(0x32);
        let resolver = Arc::new(MockResolver::new());
        resolver.insert(initiator.service_did(), initiator.key_id(), *initiator.key_material());
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig {
            // Empty allowlist — every signed signature falls outside.
            accepted_algorithms: &[],
            ..SyncHandshakeVerificationConfig::default()
        };
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SyncHandshakeVerificationError::UnsupportedAlgorithm(SignatureAlgorithm::Ed25519)
        ));
    }

    /// NonceTrackerBackend: tracker returns BackendUnavailable.
    /// The Mutex inside DefaultHandshakeNonceTracker is rarely
    /// poisoned in normal use; we use a custom failing tracker.
    #[tokio::test]
    async fn verify_sync_hello_returns_nonce_tracker_backend() {
        struct FailingTracker;
        impl crate::wire::HandshakeNonceTracker for FailingTracker {
            fn check_and_record(
                &self,
                _initiator: &ServiceIdentity,
                _nonce: &SessionNonce,
                _observed_at: SystemTime,
            ) -> Result<crate::wire::NonceFreshness, NonceTrackerError> {
                Err(NonceTrackerError::BackendUnavailable)
            }
            fn replay_window(&self) -> Duration {
                Duration::from_secs(60)
            }
        }
        let (bytes, initiator, _sk) = build_valid_hello(0x33);
        let resolver = Arc::new(MockResolver::new());
        resolver.insert(initiator.service_did(), initiator.key_id(), *initiator.key_material());
        let cfg = SyncHandshakeVerificationConfig::default();
        let err = verify_sync_hello(
            &bytes,
            &FailingTracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SyncHandshakeVerificationError::NonceTrackerBackend(_)
        ));
    }

    /// NotYetValid: `at` field is in the future beyond skew
    /// tolerance. Constructed by stamping `at = now + 1 hour`.
    #[tokio::test]
    async fn verify_sync_hello_returns_not_yet_valid() {
        let (initiator, sk) = make_initiator_identity(0x34);
        let resolver = handshake_test_resolver(&initiator);
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();
        let nonce = SessionNonce::from_bytes([0xAA; 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Bidirectional,
        };
        let at = SystemTime::now() + Duration::from_secs(3600);
        let sign_input = crate::wire::hello_sign_input(&initiator, SemVer::new(1, 0, 0), &nonce, &scope, at);
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let hello = SyncChannelHello {
            initiator_identity: initiator,
            initiator_lexicon_set_version: SemVer::new(1, 0, 0),
            proposed_session_nonce: nonce,
            requested_scope: scope,
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SyncHandshakeVerificationError::NotYetValid));
    }

    /// TooOld: `at` field is more than `max_clock_skew` in the
    /// past.
    #[tokio::test]
    async fn verify_sync_hello_returns_too_old() {
        let (initiator, sk) = make_initiator_identity(0x35);
        let resolver = handshake_test_resolver(&initiator);
        let tracker = crate::wire::DefaultHandshakeNonceTracker::new();
        let cfg = SyncHandshakeVerificationConfig::default();
        let nonce = SessionNonce::from_bytes([0xBB; 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Bidirectional,
        };
        // `at = now - 1 hour`, well past the default 30s skew.
        let at = SystemTime::now() - Duration::from_secs(3600);
        let sign_input = crate::wire::hello_sign_input(&initiator, SemVer::new(1, 0, 0), &nonce, &scope, at);
        let sig = crate::wire::sign_handshake_payload(&sk, &sign_input);
        let hello = SyncChannelHello {
            initiator_identity: initiator,
            initiator_lexicon_set_version: SemVer::new(1, 0, 0),
            proposed_session_nonce: nonce,
            requested_scope: scope,
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);
        let err = verify_sync_hello(
            &bytes,
            &tracker,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SyncHandshakeVerificationError::TooOld));
    }

    /// CounterpartyIdentityMismatch: verify_sync_response is
    /// supplied an `expected_responder_did` that does not match
    /// the responder's identity carried in the message.
    #[tokio::test]
    async fn verify_sync_response_returns_counterparty_identity_mismatch() {
        // Build a valid Accept response signed by responder A,
        // but verify against expected responder B.
        let (responder_a, sk_a) = make_initiator_identity(0x40);
        let resolver = handshake_test_resolver(&responder_a);
        let cfg = SyncHandshakeVerificationConfig::default();
        let session_id = SessionId::from_bytes([0x77; 32]);
        let scope = SyncRequestedScope {
            nsids: smallvec::SmallVec::new(),
            time_window: None,
            direction: crate::wire::SyncDirection::Bidirectional,
        };
        let at = SystemTime::now();
        let sign_input = crate::wire::accept_sign_input(
            &responder_a, SemVer::new(1, 0, 0), &session_id, &scope, at,
        );
        let sig = crate::wire::sign_handshake_payload(&sk_a, &sign_input);
        let accept = SyncChannelAccept {
            responder_identity: responder_a.clone(),
            responder_lexicon_set_version: SemVer::new(1, 0, 0),
            session_id,
            negotiated_scope: scope,
            responder_signature: sig,
            at,
        };
        let mut bytes = vec![0x00];
        bytes.extend(accept_to_wire_bytes(&accept));

        // Expected responder B (different DID).
        let did_b = Did::new("did:plc:differentresponder000").unwrap();

        let err = verify_sync_response(
            &bytes,
            &did_b,
            resolver.as_ref() as &dyn DidResolver,
            &cfg,
            deadline(),
            TraceId::from_bytes([0; 16]),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SyncHandshakeVerificationError::CounterpartyIdentityMismatch
        ));
    }
}

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
//! [`crate::verification::VerifiedHandshake`] /
//! [`crate::verification::VerifiedSyncMessage`] (§7.5) remain
//! Phase-4d-stubbed.
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
use crate::wire::{
    decode_wire_envelope, wire_envelope_is_canonical, CapabilityClaim, JwtNonce,
    NonceFreshness, NonceIssuerKey, NoncePrincipal, NonceTracker, NonceTrackerError,
    ResourceScope, CLAIM_DOMAIN_TAG, MAX_CAPABILITY_CLAIM_SIZE,
};

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

/// Verified sync-channel handshake evidence (§7.5).
///
/// Constructible only via the handshake-verification path
/// (Phase 4). Phase 1 ships only the type shape so
/// [`crate::ingress::from_sync_channel_handshake`] compiles.
#[derive(Debug, Clone)]
pub struct VerifiedHandshake {
    peer: ServiceIdentity,
    session_id: crate::identity::SessionId,
    handshake_at: SystemTime,
    _private: PhantomData<sealed::Token>,
}

impl VerifiedHandshake {
    /// Borrow the peer identity.
    #[must_use]
    pub fn peer(&self) -> &ServiceIdentity {
        &self.peer
    }

    /// Return the session id issued at handshake.
    #[must_use]
    pub fn session_id(&self) -> crate::identity::SessionId {
        self.session_id
    }

    /// Return the handshake timestamp.
    #[must_use]
    pub fn handshake_at(&self) -> SystemTime {
        self.handshake_at
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
    _trace_id: TraceId,
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
        .resolve(&issuer, deadline)
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
        // string form — array support is a chainlinked extension
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
            // shape. See chainlink for the shape-vs-reality
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
/// the `p256` / `k256` crate dependencies; chainlinks track the
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
    ) -> Self {
        VerifiedCapabilityClaim {
            issuer,
            subject,
            capabilities,
            resource_scope,
            trace_id,
            issued_at,
            expires_at,
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
    /// Audience mismatch. Per Phase 4a chainlink #27, the `got`
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
    _trace_id: TraceId,
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

    // 6. Audience equality. Per Phase 4a chainlink #27, the `got`
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

    // 10. Issuer DID resolution + signing-key selection.
    let document = resolver
        .resolve(issuer.service_did(), deadline)
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

    // 13. Construct VerifiedCapabilityClaim.
    Ok(VerifiedCapabilityClaim::new_internal(
        issuer,
        subject,
        capabilities,
        resource_scope,
        trace_id_field,
        issued_at,
        expires_at,
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
    // Phase 4c (resolves chainlink #35): walk both the current
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
            // Phase 4a chainlink #26: ES256/ES256K primitives
            // ship in a later sub-phase. Phase 4b keeps the same
            // stub posture for capability-claim verification.
            Err(ClaimVerificationError::UnsupportedAlgorithm(algorithm))
        }
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
        ) -> Result<DidDocument, DidResolutionError> {
            self.documents
                .lock()
                .unwrap()
                .get(did.as_str())
                .cloned()
                .unwrap_or(Err(DidResolutionError::NotFound))
        }

        async fn invalidate(&self, _did: &Did) {}
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
        )
        .await
        .unwrap_err();
        match err {
            ClaimVerificationError::WrongAudience { got, .. } => {
                // Phase 4a chainlink #27: `got` is a Did, not a
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
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ClaimVerificationError::UnsupportedAlgorithm(SignatureAlgorithm::Ed25519)
        ));
    }

    /// §4.8 W12 / chainlink #35 (Phase 4c): a claim signed by a
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
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClaimVerificationError::IssuerKeyNotInDocument));
    }
}

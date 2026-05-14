//! §7.2 / §7.5 verification submodule.
//!
//! Phase 4a wires §7.2 — the JWT verification chain — through
//! [`verify_jwt`]. Phase 1 shipped the [`VerifiedJwt`] type with
//! private fields and a crate-internal constructor; Phase 4a wires
//! the constructor body so that all five §7.2 stages (parse →
//! resolve key → verify signature → verify claims → construct
//! `VerifiedJwt`) execute on every authenticated request.
//!
//! [`VerifiedHandshake`] (§7.5) remains Phase-4d-stubbed.
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

use crate::identity::{
    KeyId, PublicKey, ServiceIdentity, SignatureAlgorithm, TraceId,
};
use crate::proto::Did;
use crate::resolver::{DidResolutionError, DidResolver};
use crate::sealed;
use crate::wire::JwtNonce;

/// JWT that passed signature **and** claim verification (§7.2).
///
/// Constructible only via [`verify_jwt`]; consumers receiving a
/// [`VerifiedJwt`] need not re-verify or trust the caller.
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
/// module emits [`crate::UserAuditEvent::CapabilityIssuanceDenied`]
/// at the ingress chokepoint with
/// [`crate::DenialReason::JwtVerificationFailed`] carrying the
/// returned error.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_config_default_is_ed25519_only() {
        // §7.2 default allowlist commitment.
        let c = JwtVerificationConfig::default();
        assert_eq!(c.accepted_algorithms, &[SignatureAlgorithm::Ed25519]);
        assert!(!c.require_nonce);
    }
}

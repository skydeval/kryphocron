//! §7.2 / §7.5 verification submodule.
//!
//! Phase 1 ships the **type shape** — `VerifiedJwt` and
//! `VerifiedHandshake` with private fields and crate-internal
//! constructors. These types are unforgeable in safe code
//! (consumers can only obtain them by calling `verify_jwt` /
//! the handshake-verification path, both of which are
//! Phase-4-stubbed).
//!
//! See §7.2 for JWT verification flow, §7.5 for the sync-handshake
//! protocol.

use core::marker::PhantomData;
use std::time::{Duration, Instant, SystemTime};

use smallvec::SmallVec;
use thiserror::Error;

use crate::identity::{ServiceIdentity, SignatureAlgorithm, TraceId};
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

/// Verify a raw JWT against the configured DID resolver
/// (§7.2).
///
/// **Phase 1 stub.** Phase 4 wires:
///
/// 1. Authorization-header parsing.
/// 2. JWT structural parse.
/// 3. DID resolution to obtain signing key.
/// 4. Signature verification.
/// 5. Claim verification (iss/aud/exp/iat/nbf/nonce).
///
/// # Errors
///
/// Returns [`JwtVerificationError`] on any failure.
pub async fn verify_jwt(
    _raw: &str,
    _local_audience: &ServiceIdentity,
    _resolver: &dyn DidResolver,
    _config: &JwtVerificationConfig,
    _deadline: Instant,
    _trace_id: TraceId,
) -> Result<VerifiedJwt, JwtVerificationError> {
    unimplemented!("§7.2 verify_jwt: Phase 4 wires the verification chain");
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.8 nonce tracker + replay-protection types (round-4 reshape).

use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::identity::KeyId;
use crate::proto::Did;

/// 16-byte capability-claim nonce (§4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimNonce([u8; 16]);

impl ClaimNonce {
    /// Construct a [`ClaimNonce`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        ClaimNonce(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// 16-byte JWT nonce (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwtNonce([u8; 16]);

impl JwtNonce {
    /// Construct a [`JwtNonce`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        JwtNonce(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Discriminator for the two wire vocabularies that share the
/// unified nonce tracker (§4.8 round-4 reshape).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NonceKind {
    /// Nonce from a [`crate::wire::CapabilityClaim`].
    CapabilityClaim,
    /// Nonce from a [`crate::verification::VerifiedJwt`] bearer
    /// token (§7.2).
    Jwt,
}

/// Principal half of [`NonceIssuerKey`] (§4.8 round-4 reshape).
///
/// Stable subset of identity that survives non-signing-key
/// rotation but rolls over on signing-key rotation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NoncePrincipal {
    /// Service-issued claim.
    Service(Did),
    /// User-issued JWT.
    UserJwt(Did),
}

/// Stable subset of issuer identity used as a [`NonceTracker`]
/// key (§4.8 round-4 reshape).
///
/// Composed of `(NoncePrincipal, KeyId)`. The principal identifies
/// *who* is signing; the [`KeyId`] identifies *which specific
/// signing key* was used. Rotation produces a new [`KeyId`] so
/// nonces issued under different keys are tracked in distinct
/// namespaces — but non-signing-key rotation changes leave the
/// tracker key stable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonceIssuerKey {
    /// Principal.
    pub principal: NoncePrincipal,
    /// Signing key id.
    pub key_id: KeyId,
}

/// Result of a [`NonceTracker::record`] call (§4.8).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceFreshness {
    /// Nonce not previously observed.
    Fresh,
    /// Nonce previously observed at the given instant.
    Replay {
        /// When this nonce was first seen.
        first_seen_at: SystemTime,
    },
}

/// Backend-side failure for [`NonceTracker`] implementations
/// (§4.8).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NonceTrackerError {
    /// Tracker backend is overcapacity. Operators surface this
    /// as a fail-closed signal at the substrate boundary.
    #[error("nonce tracker over capacity")]
    OverCapacity,
    /// Backend unavailable (e.g., network-backed store
    /// unreachable).
    #[error("nonce tracker backend unavailable")]
    BackendUnavailable,
}

/// Unified nonce tracker (§4.8 round-4 reshape).
///
/// One tracker per substrate process. Both
/// [`crate::wire::CapabilityClaim`] nonces and
/// [`crate::verification::VerifiedJwt`] nonces flow through the
/// same tracker. Implementations are operator-supplied;
/// the crate ships an in-memory default implementation
/// ([`crate::wire::DefaultNonceTracker`]).
///
/// Retention window must be ≥
/// `MAX_CLOCK_SKEW + max(MAX_CLAIM_VALIDITY, MAX_JWT_VALIDITY)`.
pub trait NonceTracker: Send + Sync {
    /// Record a nonce observation; return whether it was fresh
    /// or a replay.
    ///
    /// # Errors
    ///
    /// Returns [`NonceTrackerError`] if the backend cannot
    /// service the request.
    fn record(
        &self,
        kind: NonceKind,
        issuer: &NonceIssuerKey,
        nonce_bytes: &[u8; 16],
        observed_at: SystemTime,
    ) -> Result<NonceFreshness, NonceTrackerError>;

    /// Retention window the tracker enforces.
    fn retention_window(&self) -> Duration;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_issuer_key_is_principal_plus_key_id_round_4_reshape() {
        // §4.8 round-4 reshape pin: NonceIssuerKey is the stable
        // (NoncePrincipal, KeyId) tuple. Construction here exercises
        // the field shape; if a future refactor removes either
        // field, this test fails to compile.
        let k = NonceIssuerKey {
            principal: NoncePrincipal::Service(Did::new("did:plc:example").unwrap()),
            key_id: KeyId::from_bytes([0; 32]),
        };
        match &k.principal {
            NoncePrincipal::Service(_) | NoncePrincipal::UserJwt(_) => {}
        }
        let _ = k.key_id;
    }

    #[test]
    fn nonce_kind_has_capability_claim_and_jwt() {
        // §4.8 round-4: unified tracker over both vocabularies.
        let _c = NonceKind::CapabilityClaim;
        let _j = NonceKind::Jwt;
    }

    #[test]
    fn nonce_freshness_has_fresh_and_replay() {
        let _f = NonceFreshness::Fresh;
        let _r = NonceFreshness::Replay {
            first_seen_at: std::time::SystemTime::UNIX_EPOCH,
        };
    }
}

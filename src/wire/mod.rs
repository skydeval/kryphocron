//! §4.8 wire-level capability claims, attribution chains, and
//! delegation-receipt machinery.
//!
//! Phase 1 ships the **type vocabulary**. The actual deterministic
//! CBOR serialization, signature verification, and rotation-history
//! resolution land in Phase 4 (§7).
//!
//! The wire types are surfaced at the crate root via `pub use`
//! so consumers refer to them without traversing the `wire`
//! submodule path; §9.1's committed public modules do not include
//! `wire` as a separate module, but the types it ships are part
//! of the public API surface.

mod claim;
mod nonce;
mod receipt;
mod signature;

pub use self::claim::{
    CapabilityClaim, ClaimConstructionError, ClaimOrigin, ResourceScope, ScopeVariantName,
    MAX_CLAIM_VALIDITY,
};
pub use self::nonce::{
    ClaimNonce, JwtNonce, NonceFreshness, NonceIssuerKey, NonceKind, NoncePrincipal,
    NonceTracker, NonceTrackerError,
};
pub use self::receipt::{
    AttributionChainWire, AttributionEntryWire, AttributionPrincipal, DelegationReceipt,
    DelegationReceiptPayload, ReceiptVerificationFailure,
};
pub use self::signature::ClaimSignature;

/// Maximum entries in an [`AttributionChainWire`] (§4.8). Matches
/// the in-process [`crate::ingress::MAX_CHAIN_DEPTH`].
pub const MAX_ROTATION_DEPTH: usize = crate::identity::MAX_ROTATION_DEPTH;

//! §7.3 DID resolution and §7.7 federation-peer-trust trait
//! surfaces.
//!
//! Phase 1 ships **trait shapes only**. Concrete implementations
//! (PLC directory client, did:web HTTPS fetcher,
//! `ConfigFilePeerTrustResolver`) land in Phase 4.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;

use crate::identity::{KeyId, PublicKey};
use crate::proto::Did;

/// DID document subset the substrate consumes.
///
/// Phase 1 ships a minimal shape: the current verification methods
/// (key id → public key) plus an optional rotation history.
/// Phase 4 extends with service endpoints and the full §7.3
/// caching semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DidDocument {
    /// The DID this document describes.
    pub did: Did,
    /// Currently-active verification methods keyed by key id.
    pub verification_methods: Vec<(KeyId, PublicKey)>,
    /// Historical key rotations, oldest first.
    pub rotation_history: Vec<(KeyId, PublicKey)>,
}

/// DID resolution failure (§7.3).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DidResolutionError {
    /// DID does not exist in the chosen registry.
    #[error("DID not found")]
    NotFound,
    /// DID document was structurally malformed.
    #[error("DID document malformed")]
    Malformed,
    /// Resolver returned no answer within `deadline`.
    #[error("DID resolution exceeded deadline")]
    DeadlineExceeded,
    /// DID method (did:plc, did:web, …) is not supported by the
    /// configured resolver.
    #[error("DID method not supported: {0}")]
    MethodNotSupported(String),
    /// Upstream resolution infrastructure failed.
    #[error("DID resolution upstream error: {0}")]
    UpstreamError(String),
}

/// Asynchronous DID resolver (§7.3).
///
/// All methods accept a `deadline: Instant`. Implementations
/// **must** return a structured result rather than blocking past
/// the deadline. Resolver implementations backed by external
/// services (PLC directory HTTP, did:web HTTPS fetch) honor the
/// deadline against upstream latency.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Resolve `did` to a [`DidDocument`].
    async fn resolve(
        &self,
        did: &Did,
        deadline: Instant,
    ) -> Result<DidDocument, DidResolutionError>;

    /// Invalidate the cached document for `did`. Operators use
    /// this on out-of-band signals (security advisory, user
    /// report).
    async fn invalidate(&self, did: &Did);
}

/// Federation-peer kind (§7.7 round-4 reshape: distinct
/// `Internal` vs `Federation` peers).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerKind {
    /// Substrate-internal peer: operator-owned, full-trust
    /// baseline.
    Internal,
    /// External federation peer: operator-managed trust per
    /// declaration.
    Federation,
}

/// Per-peer health snapshot (§7.7 round-4: mandatory
/// `peer_health`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHealth {
    /// Whether the peer is currently considered reachable.
    pub reachable: bool,
    /// When the resolver last observed activity from this peer.
    pub last_observed_at: std::time::SystemTime,
    /// Operator-visible health notes. Bounded length (§7.5
    /// round-5 patch bound `PeerHealth.operator_notes`); Phase 4
    /// enforces the cap.
    pub operator_notes: String,
}

/// Trust query for a specific cross-peer operation (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TrustQuery {
    /// The peer DID being queried about.
    pub peer: Did,
    /// What operation is being attempted.
    pub operation: TrustOperation,
}

/// What cross-peer operation a [`TrustQuery`] is about (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustOperation {
    /// Accept a sync-channel handshake from this peer.
    AcceptSyncHandshake,
    /// Accept a capability claim issued by this peer.
    AcceptCapabilityClaim,
    /// Replicate a record from this peer.
    ReplicateRecord,
}

/// Trust resolver decision (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustDecision {
    /// Accept the operation.
    Accept,
    /// Reject the operation.
    Reject,
}

/// Federation-peer trust resolver (§7.7).
///
/// Operator-managed; the crate provides the trait surface, not
/// the policy.
#[async_trait]
pub trait PeerTrustResolver: Send + Sync {
    /// Decide whether to trust `query`. Honors `deadline` against
    /// any upstream lookups.
    async fn trust_for_operation(
        &self,
        query: &TrustQuery,
        deadline: Instant,
    ) -> Result<TrustDecision, PeerTrustError>;

    /// Record an observation about a peer's behavior; the
    /// resolver may incorporate it into future decisions.
    async fn record_peer_observation(
        &self,
        peer: &Did,
        observation: PeerObservation,
        deadline: Instant,
    ) -> Result<(), PeerTrustError>;

    /// Current health snapshot for a peer.
    async fn peer_health(
        &self,
        peer: &Did,
        deadline: Instant,
    ) -> Result<PeerHealth, PeerTrustError>;
}

/// Peer-behavior observation submitted to a
/// [`PeerTrustResolver`] (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum PeerObservation {
    /// Peer signature verified successfully.
    SignatureVerified,
    /// Peer signature failed verification.
    SignatureFailed,
    /// Peer was unreachable for a sync attempt.
    Unreachable,
    /// Peer answered within the operation's deadline.
    ResponseWithin(Duration),
}

/// Peer-trust resolver failure (§7.7).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PeerTrustError {
    /// Peer is not configured in the operator's trust set.
    #[error("peer is not configured")]
    UnknownPeer,
    /// Operation exceeded the supplied deadline.
    #[error("peer-trust query exceeded deadline")]
    DeadlineExceeded,
    /// Upstream lookup failed.
    #[error("peer-trust upstream error: {0}")]
    UpstreamError(String),
}

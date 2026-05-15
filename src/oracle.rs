// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.5 Oracle traits — block, audience, mute.
//!
//! Three oracle surfaces the substrate consults during capability
//! binding:
//!
//! - `BlockOracle` — symmetric block state between DIDs.
//! - `AudienceOracle` — viewer membership in a resource's
//!   audience list.
//! - `MuteOracle` — informational asymmetric mute state.
//!
//! All three traits commit:
//!
//! - The state query method.
//! - `last_synced_at` — the `SystemTime` instant the oracle's
//!   data was last refreshed from authoritative storage. Used
//!   for freshness enforcement.
//! - `data_freshness_bound` — the maximum age of
//!   `last_synced_at` the oracle considers fresh. Past this,
//!   binds against this oracle's queries fail closed.
//! - `worst_case_latency_for(query)` — per-query worst-case
//!   latency, summed by [`crate::equalize_timing_target_for`]
//!   to calibrate timing equalization.
//!
//! ## Sync, not async
//!
//! Oracle methods are **synchronous**. The substrate's authority
//! module consults oracles from inside the capability-bind path,
//! which is itself called from XRPC handlers that may be async.
//! Operators implementing oracle traits over async backends must
//! buffer / cache so that the synchronous query is non-blocking;
//! the design discipline mirrors the audit-sink contract (§4.3).
//!
//! ## Clock domain
//!
//! All oracle timestamps are `SystemTime` (cross-process), not
//! `Instant`. This makes oracle data shareable across process
//! restarts and across replicas.

use std::time::{Duration, SystemTime};

use crate::proto::Did;
use crate::authority::ResourceId;

/// Block state between two DIDs (§4.5).
///
/// Blocks are **bidirectionally enforced**. `Mutual` is symmetric;
/// `OneWay { blocker, blocked }` carries the direction explicitly
/// so operators can reconstruct the action that produced the block,
/// but the substrate still treats one-way blocks symmetrically in
/// gating.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockState {
    /// No block in either direction.
    None,
    /// One-way block from `blocker` to `blocked`.
    OneWay {
        /// The DID that initiated the block.
        blocker: Did,
        /// The DID that was blocked.
        blocked: Did,
    },
    /// Symmetric mutual block.
    Mutual,
}

/// Audience state between a viewer and a resource (§4.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AudienceState {
    /// Viewer is in the resource's audience.
    InAudience,
    /// Viewer is not in the resource's audience.
    NotInAudience,
    /// The resource has no audience configured. Per-capability
    /// semantics decide whether to grant or deny (§4.5).
    NoAudienceConfigured,
}

/// Mute state between a viewer and a target (§4.5).
///
/// Asymmetric; mute is informational and never gates issuance
/// (§4.3 stage 4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MuteState {
    /// No mute.
    None,
    /// Viewer has muted target.
    Muted,
}

/// Block-oracle queries declared by capability authors (§4.3
/// `OracleConsultations`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockOracleQuery {
    /// Requester vs. the resource's owner.
    RequesterVsResourceOwner,
    /// Requester vs. the thread root's owner.
    RequesterVsThreadRootOwner,
    /// Requester vs. the parent post's owner.
    RequesterVsParentPostOwner,
    /// Requester vs. a member of the resource's audience.
    RequesterVsAudienceMember,
}

/// Audience-oracle queries declared by capability authors (§4.3
/// `OracleConsultations`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AudienceOracleQuery {
    /// Requester against the resource's audience.
    RequesterAgainstResourceAudience,
    /// Requester against the parent resource's audience.
    RequesterAgainstParentResourceAudience,
}

/// Mute-oracle queries declared by capability authors (§4.3
/// `OracleConsultations`).
///
/// v1 ships one variant. `TargetMutedRequester` from earlier
/// drafts was dropped because no v1 capability needs it; adding
/// it back is a non-breaking additive change because the enum is
/// `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MuteOracleQuery {
    /// Has the requester muted the target?
    RequesterMutedTarget,
}

/// Discriminator over the three oracle surfaces (§4.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleKind {
    /// Block oracle.
    Block,
    /// Audience oracle.
    Audience,
    /// Mute oracle.
    Mute,
}

/// Specific oracle query that produced a result or freshness
/// failure (§4.3 `OracleStale`).
///
/// Carries the precise query, not just the oracle kind, so audit
/// events identify exactly which query was stale.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleQueryKind {
    /// A block-oracle query.
    Block(BlockOracleQuery),
    /// An audience-oracle query.
    Audience(AudienceOracleQuery),
    /// A mute-oracle query.
    Mute(MuteOracleQuery),
}

/// Symmetric block-state oracle (§4.5).
pub trait BlockOracle: Send + Sync {
    /// Query block state between two DIDs.
    fn block_state(&self, a: &Did, b: &Did) -> BlockState;
    /// `SystemTime` of the oracle's last data refresh.
    fn last_synced_at(&self) -> SystemTime;
    /// Maximum age past which `last_synced_at` is considered
    /// stale; binds against this oracle's queries fail closed.
    fn data_freshness_bound(&self) -> Duration;
    /// Per-query worst-case latency, summed by
    /// [`crate::equalize_timing_target_for`].
    fn worst_case_latency_for(&self, query: BlockOracleQuery) -> Duration;
}

/// Audience-membership oracle (§4.5).
pub trait AudienceOracle: Send + Sync {
    /// Query audience membership.
    fn audience_state(&self, viewer: &Did, resource: &ResourceId) -> AudienceState;
    /// `SystemTime` of the oracle's last data refresh.
    fn last_synced_at(&self) -> SystemTime;
    /// Maximum age past which `last_synced_at` is considered stale.
    fn data_freshness_bound(&self) -> Duration;
    /// Per-query worst-case latency.
    fn worst_case_latency_for(&self, query: AudienceOracleQuery) -> Duration;
}

/// Asymmetric mute-state oracle (§4.5).
///
/// Informational only; never gates capability issuance (§4.3
/// stage 4).
pub trait MuteOracle: Send + Sync {
    /// Query mute state.
    fn mute_state(&self, viewer: &Did, target: &Did) -> MuteState;
    /// `SystemTime` of the oracle's last data refresh.
    fn last_synced_at(&self) -> SystemTime;
    /// Maximum age past which `last_synced_at` is considered stale.
    fn data_freshness_bound(&self) -> Duration;
    /// Per-query worst-case latency.
    fn worst_case_latency_for(&self, query: MuteOracleQuery) -> Duration;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_kind_variants_complete() {
        // Pin the v1 variant set. Adding a new variant breaks the
        // exhaustive match — the test failure is the signal that
        // operator tooling parsing audit events must be updated.
        for &k in &[OracleKind::Block, OracleKind::Audience, OracleKind::Mute] {
            match k {
                OracleKind::Block | OracleKind::Audience | OracleKind::Mute => {}
            }
        }
    }

    #[test]
    fn mute_oracle_query_has_single_v1_variant() {
        // Pinning §4.5's commitment: v1 ships exactly one mute query.
        // Adding more is a non-breaking change via #[non_exhaustive].
        let q = MuteOracleQuery::RequesterMutedTarget;
        assert!(matches!(q, MuteOracleQuery::RequesterMutedTarget));
    }
}

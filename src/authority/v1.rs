// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hand-written v1 capability marker types (§4.3).
//!
//! v0.1 hand-writes the capability declarations the §4.3
//! `capability!` / `compose_capability!` macros would generate.
//! The sealed-trait pattern in [`crate::authority::capability`]
//! preserves the §4.3 "single source of truth" property while
//! the macro pipeline is operator-pluggable rather than
//! crate-mandatory.
//!
//! Each capability:
//!
//! 1. Defines a zero-sized marker struct.
//! 2. Implements [`sealed::Sealed`] (gating the trait).
//! 3. Implements the corresponding class trait
//!    ([`UserCapability`], [`Endpoint`], [`SubstrateScope`],
//!    [`ModerationCapability`]).
//! 4. Defines an empty `*OracleResults` struct gated by
//!    [`OracleResultsForCapability`].
//! 5. Implements [`IssuancePolicy`] for user-class capabilities.
//!    The v1 predicate bodies are permissive (always-Ok) — v0.1
//!    delegates per-capability policy to the bind path's oracle
//!    consultations + audience checks. A future enrichment pass
//!    can swap the permissive predicates for capability-specific
//!    logic without touching the trait surface.
//!
//! Per-capability query sets are v0.1 interpretations pending
//! operator-policy review.

use std::time::Duration;

use crate::authority::capability::{
    CapabilityKind, CapabilitySemantics, Endpoint, ModerationCapability,
    OracleConsultations, OracleResultsForCapability, SubstrateScope, UserCapability,
};
use crate::authority::predicate::{DenialReason, IssuancePolicy, PredicateContext};
use crate::authority::subjects::{
    ChannelBinding, ManageAudienceSubject, ModerationSubject, ResourceId, ScopeSelector,
};
use crate::oracle::{
    AudienceOracleQuery, AudienceState, BlockOracleQuery, BlockState,
};
use crate::sealed;

// ============================================================
// Empty `*OracleResults` placeholder helper.
// ============================================================
//
// v0.1's hand-written capabilities carry typed `OracleResults`
// structs that name the consulted queries. The fields are
// populated by the §4.3 pipeline implementation; outside the
// pipeline they are construct-only with `Default` impls.

macro_rules! capability_marker {
    (
        $marker:ident,
        $class:ident,
        $results:ident,
        kind: $kind:expr,
        max_age: $max_age:expr,
        name: $name:literal,
        subject: $subject:ty,
        semantics: $sem:expr,
        block: [$($block_q:expr),* $(,)?],
        audience: [$($aud_q:expr),* $(,)?],
        mute: [$($mute_q:expr),* $(,)?],
        results_block: [$($rb_field:ident),* $(,)?],
        results_audience: [$($ra_field:ident),* $(,)?],
        results_mute: [$($rm_field:ident),* $(,)?],
    ) => {
        /// User-class capability marker (§4.3).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $marker;

        impl sealed::Sealed for $marker {}

        impl $class for $marker {
            type Subject = $subject;
            type OracleResults = $results;
            const KIND: CapabilityKind = $kind;
            const MAX_AGE: Duration = $max_age;
            const NAME: &'static str = $name;
            const ORACLE_CONSULTATIONS: OracleConsultations = OracleConsultations {
                block: &[$($block_q,)*],
                audience: &[$($aud_q,)*],
                mute: &[$($mute_q,)*],
            };
            const SEMANTICS: CapabilitySemantics = $sem;
        }

        /// Per-capability oracle-results struct (§4.3 macro
        /// expansion equivalent). Fields are populated by the
        /// §4.3 pipeline; outside the pipeline they are
        /// default-initialized.
        #[derive(Debug, Clone, Default)]
        #[non_exhaustive]
        pub struct $results {
            $(
                /// Block-oracle query result.
                pub $rb_field: BlockState,
            )*
            $(
                /// Audience-oracle query result.
                pub $ra_field: AudienceState,
            )*
            $(
                /// Mute-oracle query result.
                pub $rm_field: crate::oracle::MuteState,
            )*
        }

        impl sealed::Sealed for $results {}

        impl OracleResultsForCapability<$marker> for $results {}
    };
}

// Default impls on the state enums power the macro-generated
// `#[derive(Default)]` on the `*OracleResults` structs. v0.1
// stub defaults: no block, no audience configured, no mute. These
// match the most-permissive starting state, which is the safe
// choice for a struct that gets *overwritten* by the §4.3 pipeline
// before predicates see it.

#[allow(clippy::derivable_impls)]
impl Default for BlockState {
    fn default() -> Self {
        BlockState::None
    }
}

#[allow(clippy::derivable_impls)]
impl Default for AudienceState {
    fn default() -> Self {
        AudienceState::NoAudienceConfigured
    }
}

#[allow(clippy::derivable_impls)]
impl Default for crate::oracle::MuteState {
    fn default() -> Self {
        crate::oracle::MuteState::None
    }
}

// ============================================================
// User-class capabilities.
// ============================================================

capability_marker! {
    ViewPrivate, UserCapability, ViewPrivateOracleResults,
    kind: CapabilityKind::ViewPrivate,
    max_age: Duration::from_secs(300),
    name: "view-private",
    subject: ResourceId,
    semantics: CapabilitySemantics::Read,
    block: [BlockOracleQuery::RequesterVsResourceOwner],
    audience: [AudienceOracleQuery::RequesterAgainstResourceAudience],
    mute: [],
    results_block: [block_requester_vs_resource_owner],
    results_audience: [audience_requester_against_resource_audience],
    results_mute: [],
}

impl IssuancePolicy for ViewPrivate {
    fn capability_predicate(
        _ctx: &PredicateContext<'_>,
        _target: &ResourceId,
        _oracle_results: &ViewPrivateOracleResults,
    ) -> Result<(), DenialReason> {
        // v0.1: permissive predicate. The bind pipeline consults
        // the block oracle at stage 2; v0.2 adds the audience
        // oracle and predicate-level audience/ownership
        // refinement.
        Ok(())
    }
}

capability_marker! {
    ParticipatePrivate, UserCapability, ParticipatePrivateOracleResults,
    kind: CapabilityKind::ParticipatePrivate,
    max_age: Duration::from_secs(60),
    name: "participate-private",
    subject: ResourceId,
    semantics: CapabilitySemantics::Write,
    block: [
        BlockOracleQuery::RequesterVsResourceOwner,
        BlockOracleQuery::RequesterVsParentPostOwner,
    ],
    audience: [AudienceOracleQuery::RequesterAgainstResourceAudience],
    mute: [],
    results_block: [
        block_requester_vs_resource_owner,
        block_requester_vs_parent_post_owner,
    ],
    results_audience: [audience_requester_against_resource_audience],
    results_mute: [],
}

impl IssuancePolicy for ParticipatePrivate {
    fn capability_predicate(
        _ctx: &PredicateContext<'_>,
        _target: &ResourceId,
        _oracle_results: &ParticipatePrivateOracleResults,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

capability_marker! {
    EditPrivatePost, UserCapability, EditPrivatePostOracleResults,
    kind: CapabilityKind::EditPrivatePost,
    max_age: Duration::from_secs(60),
    name: "edit-private-post",
    subject: ResourceId,
    semantics: CapabilitySemantics::Write,
    // Per §4.3 compose_capability! illustration: composed of
    // ViewPrivate + ParticipatePrivate; query union derived.
    block: [
        BlockOracleQuery::RequesterVsResourceOwner,
        BlockOracleQuery::RequesterVsParentPostOwner,
    ],
    audience: [AudienceOracleQuery::RequesterAgainstResourceAudience],
    mute: [],
    results_block: [
        block_requester_vs_resource_owner,
        block_requester_vs_parent_post_owner,
    ],
    results_audience: [audience_requester_against_resource_audience],
    results_mute: [],
}

impl IssuancePolicy for EditPrivatePost {
    fn capability_predicate(
        _ctx: &PredicateContext<'_>,
        _target: &ResourceId,
        _oracle_results: &EditPrivatePostOracleResults,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

capability_marker! {
    DeletePrivatePost, UserCapability, DeletePrivatePostOracleResults,
    kind: CapabilityKind::DeletePrivatePost,
    max_age: Duration::from_secs(30),
    name: "delete-private-post",
    subject: ResourceId,
    semantics: CapabilitySemantics::Write,
    block: [BlockOracleQuery::RequesterVsResourceOwner],
    audience: [],
    mute: [],
    results_block: [block_requester_vs_resource_owner],
    results_audience: [],
    results_mute: [],
}

impl IssuancePolicy for DeletePrivatePost {
    fn capability_predicate(
        _ctx: &PredicateContext<'_>,
        _target: &ResourceId,
        _oracle_results: &DeletePrivatePostOracleResults,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

capability_marker! {
    ManageAudience, UserCapability, ManageAudienceOracleResults,
    kind: CapabilityKind::ManageAudience,
    max_age: Duration::from_secs(60),
    name: "manage-audience",
    subject: ManageAudienceSubject,
    semantics: CapabilitySemantics::Write,
    block: [BlockOracleQuery::RequesterVsResourceOwner],
    audience: [],
    mute: [],
    results_block: [block_requester_vs_resource_owner],
    results_audience: [],
    results_mute: [],
}

impl IssuancePolicy for ManageAudience {
    fn capability_predicate(
        _ctx: &PredicateContext<'_>,
        _target: &ManageAudienceSubject,
        _oracle_results: &ManageAudienceOracleResults,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

// ============================================================
// Channel-class capabilities.
// ============================================================

macro_rules! channel_marker {
    ($marker:ident, $kind:expr, $max_age:expr, $name:literal $(,)?) => {
        /// Channel-class capability marker (§4.3).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $marker;

        impl sealed::Sealed for $marker {}

        impl Endpoint for $marker {
            type Subject = ChannelBinding;
            const KIND: CapabilityKind = $kind;
            const MAX_AGE: Duration = $max_age;
            const NAME: &'static str = $name;
        }
    };
}

channel_marker!(EmitToSyncChannel, CapabilityKind::EmitToSyncChannel, Duration::from_secs(60), "emit-to-sync-channel");
channel_marker!(AppViewSync, CapabilityKind::AppViewSync, Duration::from_secs(60), "appview-sync");
channel_marker!(GraphSync, CapabilityKind::GraphSync, Duration::from_secs(60), "graph-sync");

// ============================================================
// Substrate-class capabilities.
// ============================================================

macro_rules! substrate_marker {
    ($marker:ident, $kind:expr, $max_age:expr, $name:literal $(,)?) => {
        /// Substrate-class capability marker (§4.3). NEVER
        /// wire-shippable (§4.8 W6).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $marker;

        impl sealed::Sealed for $marker {}

        impl SubstrateScope for $marker {
            type Subject = ScopeSelector;
            const KIND: CapabilityKind = $kind;
            const MAX_AGE: Duration = $max_age;
            const NAME: &'static str = $name;
        }
    };
}

substrate_marker!(ScanShard, CapabilityKind::ScanShard, Duration::from_secs(120), "scan-shard");
substrate_marker!(ReplicatePrivate, CapabilityKind::ReplicatePrivate, Duration::from_secs(120), "replicate-private");
substrate_marker!(GarbageCollect, CapabilityKind::GarbageCollect, Duration::from_secs(120), "garbage-collect");

// ============================================================
// Moderation-class capabilities.
// ============================================================

macro_rules! moderation_marker {
    ($marker:ident, $kind:expr, $max_age:expr, $name:literal $(,)?) => {
        /// Moderation-class capability marker (§4.3). NEVER
        /// wire-shippable (§4.8 W6).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $marker;

        impl sealed::Sealed for $marker {}

        impl ModerationCapability for $marker {
            type Subject = ModerationSubject;
            const KIND: CapabilityKind = $kind;
            const MAX_AGE: Duration = $max_age;
            const NAME: &'static str = $name;
        }
    };
}

moderation_marker!(ModeratorRead, CapabilityKind::ModeratorRead, Duration::from_secs(30), "moderator-read");
moderation_marker!(ModeratorTakedown, CapabilityKind::ModeratorTakedown, Duration::from_secs(10), "moderator-takedown");
moderation_marker!(ModeratorRestore, CapabilityKind::ModeratorRestore, Duration::from_secs(30), "moderator-restore");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_private_constants_match_spec() {
        // §4.7 MAX_AGE upper bound for ViewPrivate is 300s.
        assert_eq!(ViewPrivate::MAX_AGE, Duration::from_secs(300));
        assert_eq!(ViewPrivate::KIND, CapabilityKind::ViewPrivate);
        assert_eq!(ViewPrivate::SEMANTICS, CapabilitySemantics::Read);
        assert_eq!(ViewPrivate::NAME, "view-private");
        assert_eq!(ViewPrivate::ORACLE_CONSULTATIONS.block.len(), 1);
        assert_eq!(ViewPrivate::ORACLE_CONSULTATIONS.audience.len(), 1);
        assert_eq!(ViewPrivate::ORACLE_CONSULTATIONS.mute.len(), 0);
    }

    #[test]
    fn participate_private_max_age_per_spec() {
        // §4.7 table: ParticipatePrivate = 60s.
        assert_eq!(ParticipatePrivate::MAX_AGE, Duration::from_secs(60));
    }

    #[test]
    fn delete_private_post_max_age_per_spec() {
        // §4.7 table: DeletePrivatePost = 30s.
        assert_eq!(DeletePrivatePost::MAX_AGE, Duration::from_secs(30));
    }

    #[test]
    fn moderator_takedown_short_max_age_per_spec() {
        // §4.7 table: ModeratorTakedown = 10s. Shortest in v1.
        assert_eq!(ModeratorTakedown::MAX_AGE, Duration::from_secs(10));
    }

    #[test]
    fn edit_private_post_is_write_semantics() {
        // §5.6 stage-0 deprecation gate fires on Write semantics.
        assert_eq!(EditPrivatePost::SEMANTICS, CapabilitySemantics::Write);
    }

    #[test]
    fn view_private_is_read_semantics() {
        // §5.6 stage-0 gate is skipped for Read.
        assert_eq!(ViewPrivate::SEMANTICS, CapabilitySemantics::Read);
    }
}

//! §4.3 capability trait hierarchies, classes, and the v1
//! capability kind enumeration.
//!
//! Four sealed trait hierarchies, one per capability class:
//!
//! - [`UserCapability`] — user-class capabilities.
//! - [`Endpoint`] — channel-class capabilities.
//! - [`SubstrateScope`] — substrate-class capabilities.
//! - [`ModerationCapability`] — moderation-class capabilities.
//!
//! All four are sealed via [`crate::sealed::Sealed`]. Concrete
//! capability marker types ([`crate::authority::v1::ViewPrivate`]
//! et al.) implement the class trait their kind belongs to.
//!
//! Phase 1 ships the v1 marker types hand-written rather than
//! macro-generated. The macro-based "single source of truth"
//! property §4.3 commits via [`capability!`] is held in Phase 1
//! by the sealed [`OracleResultsForCapability`] trait: only the
//! hand-written `*OracleResults` structs the crate ships
//! implement it. See CHAINLINKS #4.

use std::time::Duration;

use smallvec::SmallVec;

use crate::oracle::{AudienceOracleQuery, BlockOracleQuery, MuteOracleQuery};
use crate::sealed;

/// Capability-class discriminator (§4.3 `CapabilityClass`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityClass {
    /// User-class: bound to a user DID, wire-shippable with
    /// `Resource(rid)` scope only.
    User,
    /// Channel-class: substrate-internal channel operations,
    /// wire-shippable with broader scopes.
    Channel,
    /// Substrate-class: substrate-internal operations, NEVER
    /// wire-shippable.
    Substrate,
    /// Moderation-class: moderation operations, NEVER wire-
    /// shippable.
    Moderation,
}

/// Runtime discriminant naming every v1 capability (§4.3
/// `CapabilityKind`).
///
/// Capability marker types ([`crate::authority::v1::ViewPrivate`]
/// et al.) carry the matching variant in [`UserCapability::KIND`]
/// (and parallels). Mismatches at proof-binding time are runtime
/// errors per §4.3's `capability_kind` discriminant discipline.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    // ---- User-class (wire-shippable with Resource scope only). ----
    /// View a private record.
    ViewPrivate,
    /// Participate (e.g., reply) in a private thread.
    ParticipatePrivate,
    /// Edit a private post.
    EditPrivatePost,
    /// Delete a private post.
    DeletePrivatePost,
    /// Manage a resource's audience list.
    ManageAudience,

    // ---- Channel-class (wire-shippable with broader scopes). ----
    /// Emit records to the sync channel.
    EmitToSyncChannel,
    /// AppView-style sync.
    AppViewSync,
    /// Graph-layer sync.
    GraphSync,

    // ---- Substrate-class (NEVER wire-shippable). ----
    /// Scan a shard.
    ScanShard,
    /// Replicate a private record.
    ReplicatePrivate,
    /// Garbage-collect non-live records.
    GarbageCollect,

    // ---- Moderation-class (NEVER wire-shippable). ----
    /// Inspect a record for moderation purposes.
    ModeratorRead,
    /// Take down a record.
    ModeratorTakedown,
    /// Restore a previously-taken-down record.
    ModeratorRestore,
}

impl CapabilityKind {
    /// Return the capability-class this kind belongs to.
    #[must_use]
    pub fn class(&self) -> CapabilityClass {
        match self {
            CapabilityKind::ViewPrivate
            | CapabilityKind::ParticipatePrivate
            | CapabilityKind::EditPrivatePost
            | CapabilityKind::DeletePrivatePost
            | CapabilityKind::ManageAudience => CapabilityClass::User,
            CapabilityKind::EmitToSyncChannel
            | CapabilityKind::AppViewSync
            | CapabilityKind::GraphSync => CapabilityClass::Channel,
            CapabilityKind::ScanShard
            | CapabilityKind::ReplicatePrivate
            | CapabilityKind::GarbageCollect => CapabilityClass::Substrate,
            CapabilityKind::ModeratorRead
            | CapabilityKind::ModeratorTakedown
            | CapabilityKind::ModeratorRestore => CapabilityClass::Moderation,
        }
    }

    /// True iff this capability may appear in a wire
    /// [`crate::wire::CapabilityClaim`] (§4.8 W6).
    ///
    /// User-class and channel-class are wire-eligible;
    /// substrate-class and moderation-class are not.
    #[must_use]
    pub fn is_wire_eligible(&self) -> bool {
        matches!(
            self.class(),
            CapabilityClass::User | CapabilityClass::Channel
        )
    }

    /// Stable wire-encoding name for this capability kind (§4.8).
    ///
    /// Used as the canonical-CBOR text representation in
    /// [`crate::CapabilityClaim`] payloads. Distinct from
    /// `Debug`'s output, which is not a stable contract. Each
    /// returned `&'static str` is the variant's ASCII identifier
    /// in `lowerCamelCase`; the inverse is
    /// [`Self::from_wire_name`].
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            CapabilityKind::ViewPrivate => "viewPrivate",
            CapabilityKind::ParticipatePrivate => "participatePrivate",
            CapabilityKind::EditPrivatePost => "editPrivatePost",
            CapabilityKind::DeletePrivatePost => "deletePrivatePost",
            CapabilityKind::ManageAudience => "manageAudience",
            CapabilityKind::EmitToSyncChannel => "emitToSyncChannel",
            CapabilityKind::AppViewSync => "appViewSync",
            CapabilityKind::GraphSync => "graphSync",
            CapabilityKind::ScanShard => "scanShard",
            CapabilityKind::ReplicatePrivate => "replicatePrivate",
            CapabilityKind::GarbageCollect => "garbageCollect",
            CapabilityKind::ModeratorRead => "moderatorRead",
            CapabilityKind::ModeratorTakedown => "moderatorTakedown",
            CapabilityKind::ModeratorRestore => "moderatorRestore",
        }
    }

    /// Inverse of [`Self::wire_name`]. Returns `None` for unknown
    /// names — the receive-side parser surfaces this as a
    /// `Malformed` claim.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Some(match name {
            "viewPrivate" => CapabilityKind::ViewPrivate,
            "participatePrivate" => CapabilityKind::ParticipatePrivate,
            "editPrivatePost" => CapabilityKind::EditPrivatePost,
            "deletePrivatePost" => CapabilityKind::DeletePrivatePost,
            "manageAudience" => CapabilityKind::ManageAudience,
            "emitToSyncChannel" => CapabilityKind::EmitToSyncChannel,
            "appViewSync" => CapabilityKind::AppViewSync,
            "graphSync" => CapabilityKind::GraphSync,
            "scanShard" => CapabilityKind::ScanShard,
            "replicatePrivate" => CapabilityKind::ReplicatePrivate,
            "garbageCollect" => CapabilityKind::GarbageCollect,
            "moderatorRead" => CapabilityKind::ModeratorRead,
            "moderatorTakedown" => CapabilityKind::ModeratorTakedown,
            "moderatorRestore" => CapabilityKind::ModeratorRestore,
            _ => return None,
        })
    }
}

/// Capability semantics: read vs. write (§4.3 stage-0
/// deprecation gating, §5.6).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilitySemantics {
    /// Capability reads or inspects; deprecated lexicons remain
    /// accessible. Stage-0 deprecation gate is skipped.
    Read,
    /// Capability creates or modifies records. Subject to stage-0
    /// deprecation gating per §5.6.
    Write,
}

/// Set of capability kinds (§4.8 attribution-chain
/// `granted_capabilities`).
///
/// Backed by a [`SmallVec`] sized for typical chain entries
/// (most entries grant ≤4 capabilities). Construction
/// deduplicates and orders entries so that subset checks during
/// receipt verification are O(n).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    kinds: SmallVec<[CapabilityKind; 4]>,
}

impl CapabilitySet {
    /// Empty capability set.
    #[must_use]
    pub fn empty() -> Self {
        CapabilitySet::default()
    }

    /// Construct a [`CapabilitySet`] from an iterator of kinds.
    /// Duplicates are removed; ordering is normalized.
    ///
    /// Named `from_kinds` (not `from_iter`) to avoid confusion
    /// with [`std::iter::FromIterator::from_iter`]; we do not
    /// implement `FromIterator` because the normalization step
    /// (dedup + sort) makes the conversion lossy from the
    /// iterator-protocol perspective.
    pub fn from_kinds<I: IntoIterator<Item = CapabilityKind>>(iter: I) -> Self {
        let mut sv: SmallVec<[CapabilityKind; 4]> = iter.into_iter().collect();
        sv.sort_by_key(|k| *k as u8);
        sv.dedup();
        CapabilitySet { kinds: sv }
    }

    /// Borrow the kinds in normalized order.
    #[must_use]
    pub fn kinds(&self) -> &[CapabilityKind] {
        &self.kinds
    }

    /// True iff every kind in `other` is also in `self`
    /// (capability monotonicity check, §4.8 W13).
    #[must_use]
    pub fn is_superset_of(&self, other: &CapabilitySet) -> bool {
        other.kinds.iter().all(|k| self.kinds.contains(k))
    }

    /// True iff `self` is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }
}

/// Declared per-capability oracle consultation list (§4.3).
///
/// Static-`&'static [Q]` slices; each capability's marker type
/// supplies these as compile-time constants.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct OracleConsultations {
    /// Block-oracle queries to consult.
    pub block: &'static [BlockOracleQuery],
    /// Audience-oracle queries to consult.
    pub audience: &'static [AudienceOracleQuery],
    /// Mute-oracle queries to consult. Informational; never
    /// denies (§4.3 stage 4).
    pub mute: &'static [MuteOracleQuery],
}

/// Trait implemented by the per-capability `*OracleResults`
/// struct each capability marker type carries (§4.3).
///
/// Sealed: only crate-ship `*OracleResults` types implement it.
/// Consumers cannot inject custom result types into the
/// predicate signature, which preserves the §4.3 "single source
/// of truth" property even though Phase 1 hand-writes the
/// `*OracleResults` structs rather than macro-generating them.
pub trait OracleResultsForCapability<C: ?Sized>: sealed::Sealed {}

// ---- The four class traits ----

/// User-class capability trait (§4.3).
///
/// **Sealed.** Adversarial implementations from outside the crate
/// fail to compile because the crate-private `Sealed` supertrait
/// is not nameable from external crates.
///
/// ```compile_fail
/// // Outside the crate this fails: `sealed::Sealed` is not
/// // visible, so the impl is structurally illegal.
/// use kryphocron::authority::UserCapability;
/// struct EvilCapability;
/// impl UserCapability for EvilCapability {
///     type Subject = ();
///     type OracleResults = ();
///     const KIND: kryphocron::CapabilityKind = kryphocron::CapabilityKind::ViewPrivate;
///     const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);
///     const NAME: &'static str = "evil";
///     const ORACLE_CONSULTATIONS: kryphocron::authority::OracleConsultations =
///         kryphocron::authority::OracleConsultations {
///             block: &[],
///             audience: &[],
///             mute: &[],
///         };
///     const SEMANTICS: kryphocron::CapabilitySemantics =
///         kryphocron::CapabilitySemantics::Read;
/// }
/// ```
pub trait UserCapability: sealed::Sealed + 'static {
    /// The subject type this capability binds to (typically
    /// [`crate::authority::ResourceId`]).
    type Subject;
    /// The per-capability oracle-results struct.
    type OracleResults: OracleResultsForCapability<Self>;
    /// Runtime kind discriminant.
    const KIND: CapabilityKind;
    /// Maximum age (§4.7).
    const MAX_AGE: Duration;
    /// Stable human-readable name.
    const NAME: &'static str;
    /// Declared oracle consultations (§4.3).
    const ORACLE_CONSULTATIONS: OracleConsultations;
    /// Read or write semantics (§5.6 stage-0 deprecation gate).
    const SEMANTICS: CapabilitySemantics;
}

/// Channel-class capability trait (§4.3).
pub trait Endpoint: sealed::Sealed + 'static {
    /// Subject type (typically
    /// [`crate::authority::ChannelBinding`]).
    type Subject;
    /// Runtime kind.
    const KIND: CapabilityKind;
    /// Maximum age (§4.7).
    const MAX_AGE: Duration;
    /// Stable name.
    const NAME: &'static str;
}

/// Substrate-class capability trait (§4.3).
pub trait SubstrateScope: sealed::Sealed + 'static {
    /// Subject type (typically
    /// [`crate::authority::ScopeSelector`]).
    type Subject;
    /// Runtime kind.
    const KIND: CapabilityKind;
    /// Maximum age (§4.7).
    const MAX_AGE: Duration;
    /// Stable name.
    const NAME: &'static str;
}

/// Moderation-class capability trait (§4.3).
pub trait ModerationCapability: sealed::Sealed + 'static {
    /// Subject type (typically
    /// [`crate::authority::ModerationSubject`]).
    type Subject;
    /// Runtime kind.
    const KIND: CapabilityKind;
    /// Maximum age (§4.7).
    const MAX_AGE: Duration;
    /// Stable name.
    const NAME: &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_kind_class_mapping_consistent() {
        for k in [
            CapabilityKind::ViewPrivate,
            CapabilityKind::ParticipatePrivate,
            CapabilityKind::EditPrivatePost,
            CapabilityKind::DeletePrivatePost,
            CapabilityKind::ManageAudience,
        ] {
            assert_eq!(k.class(), CapabilityClass::User);
            assert!(k.is_wire_eligible());
        }
        for k in [
            CapabilityKind::EmitToSyncChannel,
            CapabilityKind::AppViewSync,
            CapabilityKind::GraphSync,
        ] {
            assert_eq!(k.class(), CapabilityClass::Channel);
            assert!(k.is_wire_eligible());
        }
        for k in [
            CapabilityKind::ScanShard,
            CapabilityKind::ReplicatePrivate,
            CapabilityKind::GarbageCollect,
        ] {
            assert_eq!(k.class(), CapabilityClass::Substrate);
            assert!(!k.is_wire_eligible(), "substrate-class is NEVER wire-eligible (§4.8 W6)");
        }
        for k in [
            CapabilityKind::ModeratorRead,
            CapabilityKind::ModeratorTakedown,
            CapabilityKind::ModeratorRestore,
        ] {
            assert_eq!(k.class(), CapabilityClass::Moderation);
            assert!(!k.is_wire_eligible(), "moderation-class is NEVER wire-eligible (§4.8 W6)");
        }
    }

    #[test]
    fn capability_set_normalizes_and_dedupes() {
        let s = CapabilitySet::from_kinds([
            CapabilityKind::EditPrivatePost,
            CapabilityKind::ViewPrivate,
            CapabilityKind::ViewPrivate,
        ]);
        assert_eq!(s.kinds().len(), 2);
        assert!(s.kinds().contains(&CapabilityKind::ViewPrivate));
        assert!(s.kinds().contains(&CapabilityKind::EditPrivatePost));
    }

    #[test]
    fn capability_set_superset_check() {
        let big = CapabilitySet::from_kinds([
            CapabilityKind::ViewPrivate,
            CapabilityKind::EditPrivatePost,
        ]);
        let small = CapabilitySet::from_kinds([CapabilityKind::ViewPrivate]);
        assert!(big.is_superset_of(&small));
        assert!(!small.is_superset_of(&big));
    }
}

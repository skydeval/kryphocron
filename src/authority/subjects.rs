// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.3 / §4.4 capability subject types.
//!
//! Subject types per capability class:
//!
//! - User-class: [`ResourceId`] (typically; `ManageAudience`
//!   takes `(ResourceId, AudienceListId)`).
//! - Endpoint (channel-class): [`ChannelBinding`].
//! - SubstrateScope (substrate-class): [`ScopeSelector`].
//! - ModerationCapability: `(ResourceId, ModerationCaseId)`.

use core::marker::PhantomData;
use std::time::SystemTime;

use thiserror::Error;

use crate::identity::SessionId;
use crate::proto::{AtUri, Did, Nsid, Rkey};
use crate::sealed;

// ============================================================
// HasResourceLocation — sealed trait for subjects carrying an
// (owner DID, lexicon NSID) pair (§4.3 / §4.4).
// ============================================================

/// Subjects whose representation includes a resource location
/// (owner [`Did`] + lexicon [`Nsid`]). Implemented by user-class
/// subjects and the inner [`ResourceId`]-bearing moderation
/// subject; not implemented for channel- / substrate-class
/// subjects (which carry no NSID at all).
///
/// Sealed: only crate-ship subject types implement it. The trait
/// powers two §4.3 bind-time concerns:
///
/// 1. **Stage 0 — lexicon-deprecation gate.** The bind path
///    extracts the NSID via [`Self::resource_nsid`] and consults
///    [`crate::KRYPHOCRON_LEXICON_REGISTRY`] (§5.6).
/// 2. **Audit-event construction.** Bind emits
///    [`crate::audit::UserAuditEvent::CapabilityBound`] /
///    [`crate::audit::ModerationAuditEvent::ModeratorInspected`]
///    et al. with `subject_repr` /
///    `target_repr: TargetRepresentation::structural_only(StructuralRepresentation::Resource { did, nsid })`,
///    which needs both pieces.
///
/// **Sealed** via the crate-private [`crate::sealed::Sealed`]
/// supertrait — external types cannot impl this trait.
pub trait HasResourceLocation: sealed::Sealed {
    /// Borrow the owner DID of the resource this subject names.
    fn resource_did(&self) -> &Did;
    /// Borrow the lexicon NSID of the resource this subject
    /// names.
    fn resource_nsid(&self) -> &Nsid;
}

/// Parsed, canonicalized record reference (§4.4).
///
/// Fields are private; construction validates per-component
/// canonicalization. URI-normalization attacks are foreclosed
/// by the type's invariants — equality checks compare canonical
/// forms, not raw input strings.
///
/// ```compile_fail
/// // Outside the crate, struct-literal construction fails: the
/// // `_private` PhantomData<sealed::Token> field cannot be
/// // named because `sealed::Token` is not pub-visible.
/// use kryphocron::ResourceId;
/// let _r = ResourceId {
///     did: kryphocron::Did::new("did:plc:x").unwrap(),
///     nsid: kryphocron::Nsid::new("a.b.c").unwrap(),
///     rkey: kryphocron::Rkey::new("r").unwrap(),
///     _private: std::marker::PhantomData,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceId {
    did: Did,
    nsid: Nsid,
    rkey: Rkey,
    _private: PhantomData<sealed::Token>,
}

impl ResourceId {
    /// Construct a [`ResourceId`] from canonicalized parts.
    ///
    /// Phase 1 ships the constructor shape; Phase 2 layers in the
    /// proto-blue canonicalization step that rejects DIDs / NSIDs
    /// / rkeys outside the lexicon-validated grammar.
    #[must_use]
    pub fn new(did: Did, nsid: Nsid, rkey: Rkey) -> Self {
        ResourceId {
            did,
            nsid,
            rkey,
            _private: PhantomData,
        }
    }

    /// Borrow the DID.
    #[must_use]
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// Borrow the NSID.
    #[must_use]
    pub fn nsid(&self) -> &Nsid {
        &self.nsid
    }

    /// Borrow the record key.
    #[must_use]
    pub fn rkey(&self) -> &Rkey {
        &self.rkey
    }
}

impl sealed::Sealed for ResourceId {}
impl HasResourceLocation for ResourceId {
    fn resource_did(&self) -> &Did {
        &self.did
    }
    fn resource_nsid(&self) -> &Nsid {
        &self.nsid
    }
}

/// Audience-list reference (§4.3 ManageAudience subject side).
///
/// Phase 1 stores an [`AtUri`]; Phase 2's lexicon work may
/// constrain the URI shape further.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AudienceListId(AtUri);

impl AudienceListId {
    /// Construct an [`AudienceListId`].
    #[must_use]
    pub fn new(uri: AtUri) -> Self {
        AudienceListId(uri)
    }

    /// Borrow the underlying URI.
    #[must_use]
    pub fn uri(&self) -> &AtUri {
        &self.0
    }
}

/// Channel-class subject: peer + session (§4.3 ChannelBinding).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelBinding {
    /// The peer service identity.
    pub peer: crate::identity::ServiceIdentity,
    /// Session identifier issued at handshake.
    pub session_id: SessionId,
}

/// 8-byte shard identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardId([u8; 8]);

impl ShardId {
    /// Construct a [`ShardId`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        ShardId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

/// Range over [`ShardId`]s (§4.3 substrate-class subjects).
///
/// Rejects empty or inverted ranges at construction — no empty-
/// range no-op can be encoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShardRange {
    start: ShardId,
    end_exclusive: ShardId,
}

impl ShardRange {
    /// Construct a [`ShardRange`] with `start < end_exclusive`.
    pub fn new(start: ShardId, end_exclusive: ShardId) -> Result<Self, ScopeError> {
        if start >= end_exclusive {
            return Err(ScopeError::EmptyOrInvertedRange);
        }
        Ok(ShardRange { start, end_exclusive })
    }

    /// Borrow the inclusive start.
    #[must_use]
    pub fn start(&self) -> ShardId {
        self.start
    }

    /// Borrow the exclusive end.
    #[must_use]
    pub fn end_exclusive(&self) -> ShardId {
        self.end_exclusive
    }
}

/// `RecordState` filter for substrate-class garbage-collect
/// scopes (§4.3).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordStateFilter {
    /// All non-live records.
    AllNonLive,
    /// Tombstoned records only.
    TombstonedOnly,
    /// Taken-down records only.
    TakenDownOnly,
    /// Sealed records only.
    SealedOnly,
}

/// Time window for substrate-class garbage-collect scopes
/// (§4.3).
///
/// Empty or inverted windows rejected at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeWindow {
    start: SystemTime,
    end_exclusive: SystemTime,
}

impl TimeWindow {
    /// Construct a [`TimeWindow`] with `start < end_exclusive`.
    pub fn new(start: SystemTime, end_exclusive: SystemTime) -> Result<Self, ScopeError> {
        if start >= end_exclusive {
            return Err(ScopeError::EmptyOrInvertedRange);
        }
        Ok(TimeWindow { start, end_exclusive })
    }

    /// Borrow the inclusive start.
    #[must_use]
    pub fn start(&self) -> SystemTime {
        self.start
    }

    /// Borrow the exclusive end.
    #[must_use]
    pub fn end_exclusive(&self) -> SystemTime {
        self.end_exclusive
    }
}

/// Substrate-class subject selector (§4.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSelector {
    /// Shard scan over a half-open shard-id range.
    Shard(ShardRange),
    /// Garbage-collection scope over a record-state filter and a
    /// time window.
    GarbageCollect {
        /// Which record states to garbage-collect.
        state_filter: RecordStateFilter,
        /// Time window over which the scope applies.
        window: TimeWindow,
    },
    /// Replicate scope: a peer + a shard range to replicate.
    Replicate {
        /// Peer service identity.
        peer: crate::identity::ServiceIdentity,
        /// Shard range to replicate.
        shard: ShardRange,
    },
}

/// Subject errors at substrate-class scope construction (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// Range was empty or inverted.
    #[error("empty or inverted range")]
    EmptyOrInvertedRange,
}

/// 16-byte moderation case identifier (§4.3).
///
/// Future constructors will use `getrandom`-style randomness via
/// the `OsRng` adapter. Phase 1 ships a manual-byte constructor
/// only; Phase 4 wires the random constructor once the substrate's
/// randomness discipline is in place. The shape is committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModerationCaseId([u8; 16]);

impl ModerationCaseId {
    /// Construct a [`ModerationCaseId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        ModerationCaseId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Composite user-class subject for `ManageAudience` (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManageAudienceSubject {
    /// The resource whose audience is being managed.
    pub resource: ResourceId,
    /// Audience-list reference.
    pub audience_list: AudienceListId,
}

impl sealed::Sealed for ManageAudienceSubject {}
impl HasResourceLocation for ManageAudienceSubject {
    fn resource_did(&self) -> &Did {
        self.resource.did()
    }
    fn resource_nsid(&self) -> &Nsid {
        self.resource.nsid()
    }
}

/// Composite moderation-class subject (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModerationSubject {
    /// The resource (or principal) targeted by the moderation
    /// action.
    pub resource: ResourceId,
    /// Moderation case id.
    pub case: ModerationCaseId,
}

impl sealed::Sealed for ModerationSubject {}
impl HasResourceLocation for ModerationSubject {
    fn resource_did(&self) -> &Did {
        self.resource.did()
    }
    fn resource_nsid(&self) -> &Nsid {
        self.resource.nsid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_range_rejects_empty() {
        let s = ShardId::from_bytes([0; 8]);
        assert!(matches!(
            ShardRange::new(s, s),
            Err(ScopeError::EmptyOrInvertedRange)
        ));
    }

    #[test]
    fn shard_range_rejects_inverted() {
        let lo = ShardId::from_bytes([0; 8]);
        let hi = ShardId::from_bytes([0xFF; 8]);
        assert!(ShardRange::new(lo, hi).is_ok());
        assert!(matches!(
            ShardRange::new(hi, lo),
            Err(ScopeError::EmptyOrInvertedRange)
        ));
    }

    /// §4.3 / §4.4 (Phase 7d): subjects with a resource location
    /// expose `did + nsid` via the sealed `HasResourceLocation`
    /// trait. ResourceId returns its own fields; ManageAudienceSubject
    /// and ModerationSubject forward to their inner ResourceId.
    #[test]
    fn has_resource_location_returns_did_and_nsid_for_all_three_impls() {
        let did = Did::new("did:plc:phase7dtest").unwrap();
        let nsid = Nsid::new("tools.kryphocron.feed.postPrivate").unwrap();
        let rkey = Rkey::new("3jzfcijpj2z2a").unwrap();
        let resource = ResourceId::new(did.clone(), nsid.clone(), rkey);

        // ResourceId: direct
        assert_eq!(resource.resource_did(), &did);
        assert_eq!(resource.resource_nsid(), &nsid);

        // ManageAudienceSubject: forwards to inner resource
        let mas = ManageAudienceSubject {
            resource: resource.clone(),
            audience_list: AudienceListId::new(
                AtUri::new("at://did:plc:x/tools.kryphocron.policy.audience/3jzfcijpj2z2a")
                    .unwrap(),
            ),
        };
        assert_eq!(mas.resource_did(), &did);
        assert_eq!(mas.resource_nsid(), &nsid);

        // ModerationSubject: forwards to inner resource
        let mod_subj = ModerationSubject {
            resource: resource.clone(),
            case: ModerationCaseId::from_bytes([0u8; 16]),
        };
        assert_eq!(mod_subj.resource_did(), &did);
        assert_eq!(mod_subj.resource_nsid(), &nsid);
    }

    #[test]
    fn resource_id_construction_does_not_expose_private_field() {
        // This test exists to verify the construction path is
        // accessible. The `_private: PhantomData<sealed::Token>`
        // field prevents struct-literal construction from outside
        // the crate; see the trybuild tests for that assertion.
        let r = ResourceId::new(
            Did::new("did:plc:example").unwrap(),
            Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            Rkey::new("3jzfcijpj2z2a").unwrap(),
        );
        assert_eq!(r.did().as_str(), "did:plc:example");
    }
}

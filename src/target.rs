//! §4.4 [`TargetRepresentation`] — structural / sensitive split.
//!
//! Audit events reference subjects via [`TargetRepresentation`].
//! The split between [`StructuralRepresentation`] (DID / NSID /
//! scope kind) and [`SensitiveRepresentation`] (encrypted blob +
//! key id) limits routine operator access: forensic detail
//! requires the segregated decryption key per §8.2.

use crate::encryption::{AuditEncryptionAlgorithm, AuditEncryptionKeyId};
use crate::identity::SessionDigest;
use crate::proto::{Did, Nsid};
use crate::authority::ModerationCaseId;

/// Audit-event subject representation (§4.4).
///
/// Carries a [`StructuralRepresentation`] always; the
/// [`SensitiveRepresentation`] is optional. When no encryption
/// resolver is installed (v1 default per §8.5), `sensitive` is
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TargetRepresentation {
    /// Routine operator-visible layer.
    pub structural: StructuralRepresentation,
    /// Encrypted forensic layer, present only when an
    /// [`crate::encryption::AuditEncryptionResolver`] is wired in.
    pub sensitive: Option<SensitiveRepresentation>,
}

impl TargetRepresentation {
    /// Construct a representation with structural detail only.
    /// Used when no audit-encryption resolver is installed.
    #[must_use]
    pub fn structural_only(structural: StructuralRepresentation) -> Self {
        TargetRepresentation {
            structural,
            sensitive: None,
        }
    }

    /// Construct a representation with both layers.
    #[must_use]
    pub fn with_sensitive(
        structural: StructuralRepresentation,
        sensitive: SensitiveRepresentation,
    ) -> Self {
        TargetRepresentation {
            structural,
            sensitive: Some(sensitive),
        }
    }
}

/// Routine-operator-visible subject layer (§4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StructuralRepresentation {
    /// User-class subject: a record reference by DID + NSID.
    Resource {
        /// Resource owner DID.
        did: Did,
        /// Resource NSID.
        nsid: Nsid,
    },
    /// Channel-class subject: a peer + a session digest.
    /// The raw [`crate::SessionId`] is **not** carried; only its
    /// keyed-hash digest, so audit consumers cannot correlate
    /// across deployments.
    Channel {
        /// Peer service DID.
        peer: Did,
        /// Keyed Blake3 of the session id under the deployment
        /// correlation key.
        session_digest: SessionDigest,
    },
    /// Substrate-class subject: a scope kind without operator-
    /// visible detail. (Detail lives in the sensitive layer if a
    /// resolver is installed.)
    Scope {
        /// Which substrate-class scope variant.
        kind: ScopeKind,
    },
    /// Moderation-class subject: target DID + moderation case id.
    Moderation {
        /// Subject of the moderation action.
        target: Did,
        /// Case identifier.
        case: ModerationCaseId,
    },
}

/// Substrate-class scope variant name (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScopeKind {
    /// Shard scan.
    Shard,
    /// Garbage collect.
    GarbageCollect,
    /// Cross-substrate replication.
    Replicate,
}

/// Forensic encrypted layer (§4.4, §8.2).
///
/// The [`crate::encryption::AuditEncryptionResolver`] installed
/// at substrate startup produces these values during emit and
/// decrypts them on forensic read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SensitiveRepresentation {
    /// Encrypted payload.
    pub encrypted_blob: Vec<u8>,
    /// Key id that produced the ciphertext.
    pub key_id: AuditEncryptionKeyId,
    /// Algorithm under which `encrypted_blob` is interpreted.
    pub algorithm: AuditEncryptionAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_representation_v1_variant_set_pinned() {
        // Pin the four variants §4.4 commits. From within the
        // defining crate the wildcard is unreachable; we drop it
        // so adding a variant in a future minor version breaks
        // this test — the failure is the intended signal that
        // operator tooling parsing audit-event subject reps must
        // be updated.
        let s = StructuralRepresentation::Resource {
            did: Did::new("did:plc:example").unwrap(),
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
        };
        match s {
            StructuralRepresentation::Resource { .. }
            | StructuralRepresentation::Channel { .. }
            | StructuralRepresentation::Scope { .. }
            | StructuralRepresentation::Moderation { .. } => {}
        }
    }

    #[test]
    fn target_representation_structural_only_has_no_sensitive() {
        let s = StructuralRepresentation::Scope {
            kind: ScopeKind::Shard,
        };
        let tr = TargetRepresentation::structural_only(s);
        assert!(tr.sensitive.is_none());
    }
}

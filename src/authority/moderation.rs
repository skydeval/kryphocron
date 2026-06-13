// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §6.7 moderator-inspection notification queue.
//!
//! `ModeratorRead` binding emits two audit events: one to the
//! moderation audit sink, and one to the resource owner's
//! `InspectionNotificationQueue`. The queue's emit side is
//! `pub(in crate::authority::moderation)`-restricted so that only
//! the [`crate::authority`] module can enqueue events; the read
//! side is `pub` so operator dashboards can drain them.
//!
//! [`InspectionNotification`] ships in §6.7's
//! [`InspectionKind`]-and-[`crate::TargetRepresentation`] shape,
//! with `notification_id` / `at` fields per §6.7's committed
//! identifiers.

use std::time::{Duration, SystemTime};

use crate::audit::ModeratorRationale;
use crate::authority::subjects::ModerationCaseId;
use crate::identity::TraceId;
use crate::proto::Did;
use crate::target::TargetRepresentation;

/// 16-byte unique notification id (§6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NotificationId([u8; 16]);

impl NotificationId {
    /// Construct a [`NotificationId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        NotificationId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// One inspection-notification event (§6.7).
///
/// Emitted on every `ModeratorRead` bind (and on takedown /
/// restore actions) to the resource owner's notification queue.
/// Owners with read access via
/// [`InspectionNotificationQueueReader`] see this event after the
/// bind that produced it.
///
/// The `trace_id` carried here is the same `trace_id` as the
/// corresponding [`crate::audit::ModerationAuditEvent`]; resource
/// owners and operators reading both streams correlate moderator
/// activity end-to-end via this shared identifier (§6.7).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionNotification {
    /// Unique notification id (§6.7).
    pub notification_id: NotificationId,
    /// Forensic trace id, shared with the corresponding
    /// `ModerationAuditEvent` (§6.7 / §6.1).
    pub trace_id: TraceId,
    /// What kind of inspection / moderation event occurred.
    pub kind: InspectionKind,
    /// Subject representation (§4.4).
    pub target_repr: TargetRepresentation,
    /// `SystemTime` of the inspection (§6.1).
    pub at: SystemTime,
}

/// Inspection event vocabulary as observed by the resource owner
/// (§6.7).
///
/// Three of the four variants pair with [`crate::audit::ModerationAuditEvent`]
/// variants via shared `trace_id`:
/// [`Self::ModeratorRead`] ↔ `ModeratorInspected`,
/// [`Self::Takedown`] ↔ `ModeratorTookDown`,
/// [`Self::Restore`] ↔ `ModeratorRestored`. The fourth,
/// [`Self::QueueOverflowed`], is a queue-internal marker.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectionKind {
    /// A moderator read a private record owned by the recipient.
    /// Paired with [`crate::audit::ModerationAuditEvent::ModeratorInspected`]
    /// via shared `trace_id`. §6.7.
    ModeratorRead {
        /// Moderation case identifier.
        case: ModerationCaseId,
        /// Moderator-declared rationale.
        rationale: ModeratorRationale,
    },
    /// The recipient's record was taken down by a moderator. §6.7.
    Takedown {
        /// Moderation case identifier.
        case: ModerationCaseId,
        /// Moderator-declared rationale.
        rationale: ModeratorRationale,
    },
    /// A previously-taken-down record owned by the recipient was
    /// restored. §6.7.
    Restore {
        /// Moderation case identifier.
        case: ModerationCaseId,
        /// Moderator-declared rationale.
        rationale: ModeratorRationale,
    },
    /// Queue capacity was exceeded and older informational events
    /// were pruned to make room. Moderator-inspection events (the
    /// variants above) are exempt from pruning; the
    /// [`Self::QueueOverflowed`] marker indicates that
    /// *informational* content was dropped, not moderator events.
    /// §6.7.
    ///
    /// **Coalescing semantics:** at most one overflow marker
    /// exists in the queue at any time. Subsequent overflows
    /// increment the existing marker's `events_dropped` field in
    /// place rather than emitting a new marker. The queue
    /// reserves one slot for the marker; the marker is exempt
    /// from pruning (it never displaces itself). On
    /// [`InspectionNotificationQueueReader::acknowledge`] of the
    /// marker, the next overflow activity creates a new marker
    /// starting from `events_dropped: 1`.
    QueueOverflowed {
        /// Total informational events dropped between
        /// acknowledgments.
        events_dropped: u32,
    },
}

/// Public queue emit-side trait (§6.7 / §4.9).
///
/// Implemented by operator-installed inspection-notification
/// queues; consumed by the moderation-class bind path
/// ([`crate::authority::ModerationProof::bind`]) to
/// fan an [`InspectionNotification`] out to the resource owner's
/// queue alongside the per-class moderation audit emission.
///
/// **Inspection emission is OUTSIDE composite-audit rollback
/// semantics** (§6.7's "notifications are diagnostic, not
/// authoritative"): bind first commits the
/// [`crate::audit::ModerationAuditEvent`] via [`crate::audit::composite_audit`],
/// then enqueues the matching inspection notification. If the
/// audit commit succeeds but the inspection enqueue fails, the
/// audit stands; the operator's queue implementation surfaces
/// the inspection failure on its own. Bind does not roll the
/// audit back on inspection-emit failure.
///
/// Operators not running an inspection-queue install
/// [`NoInspectionNotifications`] (the no-op default).
pub trait InspectionNotificationQueueImpl: Send + Sync {
    /// Enqueue `event` for the resource `owner`.
    ///
    /// Failure mode is operator-defined; the trait method returns
    /// unit. Implementations that need to surface enqueue failures
    /// out-of-band (e.g., via a side-channel monitor) do so
    /// internally — bind does not consume a structured error.
    fn enqueue(&self, owner: &Did, event: InspectionNotification);
}

/// No-op default [`InspectionNotificationQueueImpl`] (§6.7).
///
/// Operators not running an inspection-notification queue install
/// this in [`crate::ingress::AuditSinks::inspection_queue`];
/// `enqueue` returns immediately and queues nothing. The §6.7
/// inspection-notification machinery is operator-pluggable, not
/// crate-mandatory; this default lets the bind path emit
/// unconditionally without forcing every deployment to ship a
/// queue implementation.
///
/// Parallels the process-static `AuthorityId` placeholder: ship the
/// discipline, let operators upgrade to a real implementation when their
/// deployment needs the feature.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoInspectionNotifications;

impl InspectionNotificationQueueImpl for NoInspectionNotifications {
    fn enqueue(&self, _owner: &Did, _event: InspectionNotification) {
        // No-op: inspection-notification queue not configured.
    }
}

/// Public queue read-side trait (§6.7 / §4.9).
///
/// Operator dashboards consume this to surface inspection events
/// to resource owners.
pub trait InspectionNotificationQueueReader: Send + Sync {
    /// Drain the queue for a given owner.
    fn read(&self, owner: &Did) -> Vec<InspectionNotification>;
    /// Acknowledge events; they are eligible for GC after the
    /// queue's retention window. Acknowledging an
    /// [`InspectionKind::QueueOverflowed`] marker frees its
    /// reserved slot; subsequent overflow activity creates a new
    /// marker starting from `events_dropped: 1` per §6.7.
    fn acknowledge(&self, owner: &Did, event_ids: &[NotificationId]);
    /// Retention window for unacknowledged events. Recommended
    /// 90 days per §4.9 inspection-event durability.
    fn retention_window(&self) -> Duration;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{BoundedString, MAX_RATIONALE_LEN};

    fn rationale() -> ModeratorRationale {
        ModeratorRationale::Declared(
            BoundedString::<MAX_RATIONALE_LEN>::new("test rationale").unwrap(),
        )
    }

    /// §6.7 commits four `InspectionKind` variants:
    /// `ModeratorRead`, `Takedown`, `Restore`, `QueueOverflowed`.
    #[test]
    fn inspection_kind_v1_variant_set_pinned() {
        let case = ModerationCaseId::from_bytes([0u8; 16]);
        for k in [
            InspectionKind::ModeratorRead {
                case,
                rationale: rationale(),
            },
            InspectionKind::Takedown {
                case,
                rationale: rationale(),
            },
            InspectionKind::Restore {
                case,
                rationale: rationale(),
            },
            InspectionKind::QueueOverflowed { events_dropped: 0 },
        ] {
            match k {
                InspectionKind::ModeratorRead { .. }
                | InspectionKind::Takedown { .. }
                | InspectionKind::Restore { .. }
                | InspectionKind::QueueOverflowed { .. } => {}
            }
        }
    }

    /// `NoInspectionNotifications` is the no-op
    /// default operators install when not running an inspection-
    /// notification queue. `enqueue` returns immediately and
    /// queues nothing. Trait-object dispatch via
    /// `&dyn InspectionNotificationQueueImpl` works (the field
    /// shape used by [`crate::ingress::AuditSinks::inspection_queue`]).
    #[test]
    fn no_inspection_notifications_is_callable_as_trait_object() {
        let queue: &dyn InspectionNotificationQueueImpl = &NoInspectionNotifications;
        let owner = Did::new("did:plc:phase7dtest").unwrap();
        let notification = InspectionNotification {
            notification_id: NotificationId::from_bytes([0u8; 16]),
            trace_id: TraceId::from_bytes([0u8; 16]),
            kind: InspectionKind::QueueOverflowed { events_dropped: 0 },
            target_repr: TargetRepresentation::structural_only(
                crate::StructuralRepresentation::Resource {
                    did: owner.clone(),
                    nsid: crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
                },
            ),
            at: SystemTime::UNIX_EPOCH,
        };
        // The no-op should not panic, allocate, or otherwise
        // observably affect anything.
        queue.enqueue(&owner, notification);
    }

    /// §6.7 commits `InspectionNotification` with five fields:
    /// `notification_id`, `trace_id`, `kind`, `target_repr`, `at`.
    #[test]
    fn inspection_notification_v1_field_set_pinned() {
        let case = ModerationCaseId::from_bytes([0u8; 16]);
        let n = InspectionNotification {
            notification_id: NotificationId::from_bytes([0u8; 16]),
            trace_id: TraceId::from_bytes([0u8; 16]),
            kind: InspectionKind::ModeratorRead {
                case,
                rationale: rationale(),
            },
            target_repr: TargetRepresentation::structural_only(
                crate::StructuralRepresentation::Resource {
                    did: Did::new("did:plc:phase3test").unwrap(),
                    nsid: crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
                },
            ),
            at: SystemTime::UNIX_EPOCH,
        };
        // Destructure to confirm field names.
        let InspectionNotification {
            notification_id: _,
            trace_id: _,
            kind: _,
            target_repr: _,
            at: _,
        } = n;
    }
}

//! §4.9 moderator-inspection notification queue.
//!
//! `ModeratorRead` binding emits two audit events: one to the
//! moderation audit sink, and one to the resource owner's
//! `InspectionNotificationQueue`. The queue's emit side is
//! `pub(in crate::authority::moderation)`-restricted so that only
//! the [`crate::authority`] module can enqueue events; the read
//! side is `pub` so operator dashboards can drain them.

use std::time::Duration;

use crate::identity::TraceId;
use crate::proto::Did;
use crate::authority::capability::CapabilityKind;
use crate::authority::subjects::ResourceId;

/// 16-byte unique notification id (§4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NotificationId([u8; 16]);

impl NotificationId {
    /// Construct a [`NotificationId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        NotificationId(bytes)
    }
}

/// One inspection-notification event (§4.9).
///
/// Emitted on every `ModeratorRead` bind to the resource owner's
/// notification queue. Owners with read access via
/// [`InspectionNotificationQueueReader`] see this event after
/// the bind that produced it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionNotification {
    /// Unique notification id.
    pub id: NotificationId,
    /// Forensic trace id correlating to the bind.
    pub trace_id: TraceId,
    /// The capability that produced the inspection.
    pub capability: CapabilityKind,
    /// Resource that was inspected.
    pub resource: ResourceId,
    /// `SystemTime` of the inspection.
    pub inspected_at: std::time::SystemTime,
}

/// Crate-internal queue emit-side trait (§4.9).
///
/// `pub(in crate::authority::moderation)` so only this module
/// can enqueue.
pub(in crate::authority::moderation) trait InspectionNotificationQueueImpl {
    fn enqueue(&self, owner: &Did, event: InspectionNotification);
}

/// Public queue read-side trait (§4.9).
///
/// Operator dashboards consume this to surface inspection events
/// to resource owners.
pub trait InspectionNotificationQueueReader: Send + Sync {
    /// Drain the queue for a given owner.
    fn read(&self, owner: &Did) -> Vec<InspectionNotification>;
    /// Acknowledge events; they are eligible for GC after the
    /// queue's retention window.
    fn acknowledge(&self, owner: &Did, event_ids: &[NotificationId]);
    /// Retention window for unacknowledged events. Recommended
    /// 90 days per §4.9 inspection-event durability.
    fn retention_window(&self) -> Duration;
}

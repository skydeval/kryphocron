//! §4.9 audit pipeline traits, sink types, composite-audit
//! rollback machinery, fallback sink contract.
//!
//! Four parallel audit channels — user, channel, substrate,
//! moderation — plus a fallback sink for sink-panic and
//! composite-failure events. The audit pipeline is **type-routed**
//! (§4.9 A2): cross-class misrouting is a compile error because
//! each channel's sink takes a class-specific event enum.

mod composite;
mod events;
mod rate_limit;
mod sinks;

pub use self::composite::{
    composite_audit, CompositeAuditError, CompositeAuditScope, CompositeOpId,
    CompositeRollbackMarker, TRACKER_GRACE_WINDOW_DEFAULT, TRACKER_GRACE_WINDOW_MAX,
    TRACKER_SHARDS,
};
pub use self::events::{
    BatchRejectionReason, ChannelAuditEvent, ChannelCloseCause, DerivationOutcome,
    FallbackAuditEvent, ModerationAuditEvent, NarrowingKind, SubstrateAuditEvent,
    SyncPerspective, UserAuditEvent,
};
pub use self::rate_limit::{IssuanceRateLimiter, TokenBucket};
pub use self::sinks::{
    AuditError, ChannelAuditSink, FallbackAuditSink, ModerationAuditSink, Panicked,
    SinkKind, SinkPanicGuard, SubstrateAuditSink, TerminatedSinkGuard, UserAuditSink,
};

/// Audit event schema version (§9.7 / §6.9).
///
/// Phase 1 ships v1; Phase 3 (§6) revises when event vocabulary
/// solidifies.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

//! §4.9 composite-audit rollback machinery.
//!
//! [`composite_audit`] wraps a multi-sink operation. On mid-flight
//! failure, rollback markers fire on already-committed sinks; on
//! marker-emission failure, the substrate calls
//! [`crate::audit::FallbackAuditSink::record_composite_failure`].
//! On fallback failure, the substrate aborts.
//!
//! Phase 1 ships the type vocabulary and the [`composite_audit`]
//! function signature; Phase 4 wires the actual dispatch +
//! tracker GC.

use std::time::Duration;

use thiserror::Error;

use crate::identity::TraceId;

use super::sinks::{AuditError, SinkKind};

/// 16-byte composite-operation identifier (§4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompositeOpId([u8; 16]);

impl CompositeOpId {
    /// Construct a [`CompositeOpId`] from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        CompositeOpId(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Number of shards in the composite-id tracker (§4.9).
///
/// Compile-time constant; not operator-tunable at runtime in v1.
pub const TRACKER_SHARDS: usize = 16;

/// Default grace window for the composite-id tracker (§4.9).
pub const TRACKER_GRACE_WINDOW_DEFAULT: Duration = Duration::from_millis(100);

/// Hard cap on grace-window configuration (§4.9). Configurations
/// exceeding this are rejected at config-load time.
pub const TRACKER_GRACE_WINDOW_MAX: Duration = Duration::from_secs(1);

/// Composite-audit scope tracked across a multi-sink operation
/// (§4.9).
///
/// Internal fields are crate-private — operators cannot construct
/// or mutate a scope outside [`composite_audit`].
#[derive(Debug)]
pub struct CompositeAuditScope {
    trace_id: TraceId,
    composite_op_id: CompositeOpId,
    // SmallVec to avoid heap allocations for the common case of
    // ≤4 sinks per composite. Mutated only inside crate.
    sinks_committed: std::sync::Mutex<smallvec::SmallVec<[SinkKind; 4]>>,
}

impl CompositeAuditScope {
    /// Crate-internal constructor.
    #[must_use]
    pub(crate) fn new_internal(trace_id: TraceId, composite_op_id: CompositeOpId) -> Self {
        CompositeAuditScope {
            trace_id,
            composite_op_id,
            sinks_committed: std::sync::Mutex::new(smallvec::SmallVec::new()),
        }
    }

    /// Forensic trace id.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Composite op id.
    #[must_use]
    pub fn composite_op_id(&self) -> CompositeOpId {
        self.composite_op_id
    }
}

/// Composite-audit failure cases (§4.9).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompositeAuditError {
    /// Wrapped operation returned an error.
    #[error("composite op failed")]
    OpFailed,
    /// Rollback marker emission failed past
    /// [`crate::audit::FallbackAuditSink`].
    #[error("composite inconsistency unrecoverable")]
    InconsistencyUnrecoverable,
    /// Tracker is at capacity; the substrate cannot accept new
    /// composite scopes.
    #[error("composite tracker full")]
    TrackerFull,
}

/// Rollback-marker event variant (§4.9).
///
/// Constructible **only** within `crate::audit::composite`
/// (`pub(in crate::audit::composite)` per §4.9 A6 invariant).
/// Phase 1 ships the type shape; Phase 4 wires the emission
/// path through a crate-internal sink-dispatch trait.
#[derive(Debug, Clone)]
pub struct CompositeRollbackMarker {
    pub(in crate::audit::composite) trace_id: TraceId,
    pub(in crate::audit::composite) composite_op_id: CompositeOpId,
    pub(in crate::audit::composite) failing_sink: SinkKind,
}

impl CompositeRollbackMarker {
    /// Crate-internal constructor.
    #[must_use]
    pub(in crate::audit::composite) fn new_internal(
        trace_id: TraceId,
        composite_op_id: CompositeOpId,
        failing_sink: SinkKind,
    ) -> Self {
        CompositeRollbackMarker {
            trace_id,
            composite_op_id,
            failing_sink,
        }
    }
}

/// Crate-internal sink-dispatch trait (§4.9).
///
/// Routes rollback-marker events to the appropriate class sink
/// based on [`SinkKind`]. Used only by
/// [`emit_rollback_marker`]; not exposed to consumers.
pub(in crate::audit) trait SinkDispatcher {
    fn dispatch(
        &self,
        sink: SinkKind,
        event: CompositeRollbackMarker,
    ) -> Result<(), AuditError>;
}

/// Crate-internal rollback-marker emission entrypoint
/// (§4.9 A6).
#[allow(dead_code)]
pub(in crate::audit::composite) fn emit_rollback_marker(
    _scope: &CompositeAuditScope,
    _sink_dispatch: &dyn SinkDispatcher,
    _failing_sink: SinkKind,
) -> Result<(), AuditError> {
    unimplemented!("§4.9 composite::emit_rollback_marker: Phase 4 wires");
}

/// Composite-audit entrypoint (§4.9).
///
/// **Phase 1 stub.** Phase 4 wires the multi-sink commit-or-roll-
/// back machinery; in Phase 1 the function signature is exposed
/// so consumer code can compile.
///
/// # Errors
///
/// See [`CompositeAuditError`].
pub async fn composite_audit<F, R, E>(
    _trace_id: TraceId,
    _sinks: &crate::ingress::AuditSinks<'_>,
    _op: F,
) -> Result<R, CompositeAuditError>
where
    F: AsyncFnOnce(&CompositeAuditScope) -> Result<R, E>,
{
    unimplemented!("§4.9 composite_audit: Phase 4 wires the multi-sink machinery");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_grace_window_default_pinned() {
        assert_eq!(TRACKER_GRACE_WINDOW_DEFAULT, Duration::from_millis(100));
    }

    #[test]
    fn tracker_grace_window_max_pinned_at_1s() {
        // §4.9 hard cap.
        assert_eq!(TRACKER_GRACE_WINDOW_MAX, Duration::from_secs(1));
        assert!(TRACKER_GRACE_WINDOW_MAX >= TRACKER_GRACE_WINDOW_DEFAULT);
    }

    #[test]
    fn tracker_shards_pinned_at_16() {
        assert_eq!(TRACKER_SHARDS, 16);
    }
}

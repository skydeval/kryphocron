// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.9 composite-audit rollback machinery.
//!
//! Phase 4e (resolves CHAINLINKS #11 partial): `dead_code` allowed
//! at module level because composite-audit dispatch is the
//! downstream substrate's wiring responsibility — Phase 4 ships
//! the rollback vocabulary; Phase 5 / 6 may extend with concrete
//! dispatch implementations the crate itself doesn't carry.
#![allow(dead_code)]

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

use super::events::{
    ChannelAuditEvent, ModerationAuditEvent, SubstrateAuditEvent, UserAuditEvent,
};
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
/// Operators receive a `&CompositeAuditScope` inside the
/// [`composite_audit`] op closure and call the
/// [`Self::emit_user`] / [`Self::emit_channel`] /
/// [`Self::emit_substrate`] / [`Self::emit_moderation`]
/// methods to **queue** events for commit. Events are NOT
/// committed to their sinks during the op; they are queued
/// internally and flushed by [`composite_audit`] after the op
/// returns successfully. If the op returns `Err(_)`, queued
/// events are dropped (no commit, no rollback marker).
///
/// Internal fields are crate-private — operators cannot
/// construct or mutate a scope outside [`composite_audit`].
#[derive(Debug)]
pub struct CompositeAuditScope {
    trace_id: TraceId,
    composite_op_id: CompositeOpId,
    /// Queued events waiting for commit. Mutated by the op via
    /// `emit_*` methods; drained by [`composite_audit`] after
    /// the op returns Ok. Order of insertion is preserved so
    /// commit ordering matches the op's emit order within a
    /// class; cross-class commit ordering is governed by
    /// [`COMMIT_PRIORITY_ORDER`].
    queued_events: std::sync::Mutex<Vec<QueuedEvent>>,
    /// Sinks that have already received a committed event in
    /// this composite scope. Populated by [`composite_audit`]
    /// during the commit phase; consulted by the rollback path
    /// to identify which sinks need rollback markers.
    sinks_committed: std::sync::Mutex<smallvec::SmallVec<[SinkKind; 4]>>,
}

/// Queued composite-audit event awaiting commit. One variant
/// per sink class.
#[derive(Debug)]
enum QueuedEvent {
    User(UserAuditEvent),
    Channel(ChannelAuditEvent),
    Substrate(SubstrateAuditEvent),
    Moderation(ModerationAuditEvent),
}

impl QueuedEvent {
    fn class(&self) -> SinkKind {
        match self {
            QueuedEvent::User(_) => SinkKind::User,
            QueuedEvent::Channel(_) => SinkKind::Channel,
            QueuedEvent::Substrate(_) => SinkKind::Substrate,
            QueuedEvent::Moderation(_) => SinkKind::Moderation,
        }
    }
}

/// Class-priority commit order (§4.9). Substrate first
/// (most-privileged → most-diagnostic-on-failure), moderation
/// second, user third, channel last. The op's emit ordering
/// within a single class is preserved; cross-class ordering
/// follows this constant.
const COMMIT_PRIORITY_ORDER: &[SinkKind] = &[
    SinkKind::Substrate,
    SinkKind::Moderation,
    SinkKind::User,
    SinkKind::Channel,
];

impl CompositeAuditScope {
    /// Crate-internal constructor.
    #[must_use]
    pub(crate) fn new_internal(trace_id: TraceId, composite_op_id: CompositeOpId) -> Self {
        CompositeAuditScope {
            trace_id,
            composite_op_id,
            queued_events: std::sync::Mutex::new(Vec::new()),
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

    /// Queue a [`UserAuditEvent`] for commit at the end of the
    /// composite scope. The event is NOT delivered to the sink
    /// until [`composite_audit`] commits the scope.
    pub fn emit_user(&self, event: UserAuditEvent) {
        // Mutex poisoning here is treated as fatal: if a prior
        // emit panicked mid-update, the scope's queue is no
        // longer trustworthy. The expect() surfaces the panic
        // to the caller (which is op code; the panic propagates
        // out of composite_audit).
        self.queued_events
            .lock()
            .expect("composite scope queue poisoned")
            .push(QueuedEvent::User(event));
    }

    /// Queue a [`ChannelAuditEvent`] for commit.
    pub fn emit_channel(&self, event: ChannelAuditEvent) {
        self.queued_events
            .lock()
            .expect("composite scope queue poisoned")
            .push(QueuedEvent::Channel(event));
    }

    /// Queue a [`SubstrateAuditEvent`] for commit.
    pub fn emit_substrate(&self, event: SubstrateAuditEvent) {
        self.queued_events
            .lock()
            .expect("composite scope queue poisoned")
            .push(QueuedEvent::Substrate(event));
    }

    /// Queue a [`ModerationAuditEvent`] for commit.
    pub fn emit_moderation(&self, event: ModerationAuditEvent) {
        self.queued_events
            .lock()
            .expect("composite scope queue poisoned")
            .push(QueuedEvent::Moderation(event));
    }

    /// Crate-internal: drain the queued events, sorted by
    /// [`COMMIT_PRIORITY_ORDER`] (stable within each class so
    /// emit-order is preserved per class). Used by
    /// [`composite_audit`]'s commit phase.
    pub(in crate::audit::composite) fn drain_queued_events(&self) -> Vec<QueuedEvent> {
        let mut events = self
            .queued_events
            .lock()
            .expect("composite scope queue poisoned")
            .drain(..)
            .collect::<Vec<_>>();
        // Stable sort by class priority. `sort_by_key` is stable,
        // preserving emit-order within a class.
        events.sort_by_key(|e| {
            COMMIT_PRIORITY_ORDER
                .iter()
                .position(|c| *c == e.class())
                .unwrap_or(usize::MAX)
        });
        events
    }

    /// Crate-internal: record that a sink has committed an
    /// event. Used by [`composite_audit`]'s commit phase to
    /// build the rollback target list.
    pub(in crate::audit::composite) fn record_committed(&self, class: SinkKind) {
        let mut g = self
            .sinks_committed
            .lock()
            .expect("composite scope committed-set poisoned");
        if !g.contains(&class) {
            g.push(class);
        }
    }

    /// Crate-internal: snapshot of sinks that have committed,
    /// used by the rollback path.
    pub(in crate::audit::composite) fn committed_snapshot(&self) -> smallvec::SmallVec<[SinkKind; 4]> {
        self.sinks_committed
            .lock()
            .expect("composite scope committed-set poisoned")
            .clone()
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

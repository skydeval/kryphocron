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
///
/// The op's own error type `E` is returned directly via the
/// `E: From<CompositeAuditError>` bound on [`composite_audit`];
/// composite-machinery errors convert into `E` along the same
/// path. Operators define an outer error enum embedding
/// `CompositeAuditError` plus their op-specific variants.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompositeAuditError {
    /// A sink's `record(event)` call failed during the commit
    /// phase (after the op returned Ok). Identifies which class
    /// failed and the underlying [`AuditError`]. Rollback
    /// markers fire for any sinks that committed before this
    /// failure.
    #[error("composite commit failed at {class:?} sink: {source}")]
    SinkCommitFailed {
        /// Which sink class failed to commit.
        class: SinkKind,
        /// The underlying sink error.
        source: AuditError,
    },
    /// A rollback marker dispatch failed. Identifies which
    /// rollback target failed and the underlying error.
    /// composite_audit escalates to
    /// [`crate::audit::FallbackAuditSink::record_composite_failure`]
    /// after a rollback dispatch failure; this variant captures
    /// the rollback failure that triggered the escalation.
    #[error("composite rollback dispatch failed at {class:?} sink: {source}")]
    RollbackDispatchFailed {
        /// Which sink class the rollback marker targeted.
        class: SinkKind,
        /// The underlying dispatch error.
        source: AuditError,
    },
    /// Rollback marker emission failed past
    /// [`crate::audit::FallbackAuditSink::record_composite_failure`].
    /// Last-resort error when even the fallback escalation
    /// panics. Operators should treat this as substrate-fatal.
    #[error("composite inconsistency unrecoverable (fallback sink panicked)")]
    InconsistencyUnrecoverable,
    /// Tracker is at capacity; the substrate cannot accept new
    /// composite scopes. Reserved for the per-process
    /// [`CompositeOpId`] tracker that lands in a future cycle;
    /// not currently emitted by [`composite_audit`].
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
/// [`emit_rollback_marker`]; not exposed to consumers. The
/// concrete implementation [`AuditSinksDispatcher`] wraps
/// [`crate::ingress::AuditSinks`] and constructs the per-class
/// `CompositeRollbackMarker` event variant for each sink kind.
pub(in crate::audit) trait SinkDispatcher {
    fn dispatch(
        &self,
        sink: SinkKind,
        event: CompositeRollbackMarker,
    ) -> Result<(), AuditError>;
}

/// Crate-internal [`SinkDispatcher`] implementation over
/// operator-supplied [`crate::ingress::AuditSinks`]. Routes
/// rollback markers to the per-class sink as the matching
/// `*::CompositeRollbackMarker` event variant.
pub(in crate::audit) struct AuditSinksDispatcher<'a, 'b> {
    pub(in crate::audit) sinks: &'a crate::ingress::AuditSinks<'b>,
}

impl<'a, 'b> SinkDispatcher for AuditSinksDispatcher<'a, 'b> {
    fn dispatch(
        &self,
        sink: SinkKind,
        marker: CompositeRollbackMarker,
    ) -> Result<(), AuditError> {
        let at = std::time::SystemTime::now();
        match sink {
            SinkKind::User => self.sinks.user.record(UserAuditEvent::CompositeRollbackMarker {
                trace_id: marker.trace_id,
                composite_op_id: marker.composite_op_id,
                failing_sink: marker.failing_sink,
                at,
            }),
            SinkKind::Channel => {
                self.sinks.channel.record(ChannelAuditEvent::CompositeRollbackMarker {
                    trace_id: marker.trace_id,
                    composite_op_id: marker.composite_op_id,
                    failing_sink: marker.failing_sink,
                    at,
                })
            }
            SinkKind::Substrate => {
                self.sinks.substrate.record(SubstrateAuditEvent::CompositeRollbackMarker {
                    trace_id: marker.trace_id,
                    composite_op_id: marker.composite_op_id,
                    failing_sink: marker.failing_sink,
                    at,
                })
            }
            SinkKind::Moderation => {
                self.sinks.moderation.record(ModerationAuditEvent::CompositeRollbackMarker {
                    trace_id: marker.trace_id,
                    composite_op_id: marker.composite_op_id,
                    failing_sink: marker.failing_sink,
                    at,
                })
            }
        }
    }
}

/// Crate-internal rollback-marker emission entrypoint
/// (§4.9 A6).
///
/// Constructs a [`CompositeRollbackMarker`] from the scope's
/// trace_id + composite_op_id and the supplied
/// `failing_sink`, then dispatches via the supplied
/// [`SinkDispatcher`]. Returns the dispatcher's [`AuditError`]
/// on dispatch failure; callers escalate to
/// [`crate::audit::FallbackAuditSink::record_composite_failure`]
/// at that point.
pub(in crate::audit::composite) fn emit_rollback_marker(
    scope: &CompositeAuditScope,
    sink_dispatch: &dyn SinkDispatcher,
    target_sink: SinkKind,
    failing_sink: SinkKind,
) -> Result<(), AuditError> {
    let marker = CompositeRollbackMarker::new_internal(
        scope.trace_id,
        scope.composite_op_id,
        failing_sink,
    );
    sink_dispatch.dispatch(target_sink, marker)
}

/// Composite-audit entrypoint (§4.9).
///
/// Wraps a multi-sink operation in commit-or-rollback semantics:
///
/// 1. The op closure receives a `&CompositeAuditScope` and
///    queues events via `emit_user` / `emit_channel` /
///    `emit_substrate` / `emit_moderation`. Events are NOT
///    delivered to sinks during the op.
/// 2. If the op returns `Err(e)`: queued events are dropped;
///    `Err(e)` is returned unchanged. No sink is touched. No
///    rollback markers fire (nothing committed).
/// 3. If the op returns `Ok(r)`: queued events are committed
///    to the operator-installed sinks in [`COMMIT_PRIORITY_ORDER`]
///    (substrate → moderation → user → channel). Within each
///    class, the op's emit-order is preserved.
/// 4. If a commit fails partway: rollback markers fire to all
///    sinks that already committed (deduplicated by class), in
///    reverse [`COMMIT_PRIORITY_ORDER`]. The error returned is
///    [`CompositeAuditError::SinkCommitFailed { class, source }`]
///    converted to `E` via `From<CompositeAuditError>`.
/// 5. If a rollback marker dispatch itself fails: escalates to
///    [`crate::audit::FallbackAuditSink::record_composite_failure`].
///    Returns [`CompositeAuditError::RollbackDispatchFailed`].
/// 6. If the FallbackAuditSink escalation itself panics:
///    returns [`CompositeAuditError::InconsistencyUnrecoverable`];
///    operators should treat this as substrate-fatal.
///
/// **`E: From<CompositeAuditError>`** lets the op's error type
/// embed the composite-machinery error variants. The natural
/// pattern is an operator-side enum:
///
/// ```text
/// #[derive(Debug, thiserror::Error)]
/// enum MyOpError {
///     #[error(transparent)]
///     Composite(#[from] CompositeAuditError),
///     #[error("my op-specific failure: {0}")]
///     OpSpecific(String),
/// }
/// ```
///
/// # Errors
///
/// Returns `Err(E)` either from the op directly or from
/// [`CompositeAuditError`] converted via `From`. See variant
/// docs for the failure modes.
pub async fn composite_audit<F, R, E>(
    trace_id: TraceId,
    sinks: &crate::ingress::AuditSinks<'_>,
    op: F,
) -> Result<R, E>
where
    F: AsyncFnOnce(&CompositeAuditScope) -> Result<R, E>,
    E: From<CompositeAuditError>,
{
    // Phase 7b: composite_op_id is generated fresh per scope.
    // The per-process tracker for op_id collisions / GC lands
    // in a future cycle (TRACKER_SHARDS / TRACKER_GRACE_WINDOW
    // constants are reserved).
    let composite_op_id = generate_composite_op_id();
    let scope = CompositeAuditScope::new_internal(trace_id, composite_op_id);

    // Phase 1: run the op.
    let op_result = op(&scope).await;
    let returned = match op_result {
        Ok(r) => r,
        Err(e) => {
            // Op failed — drop queued events, return E unchanged.
            // No commit, no rollback (nothing committed).
            return Err(e);
        }
    };

    // Phase 2: commit queued events in priority order.
    let queued = scope.drain_queued_events();
    let dispatcher = AuditSinksDispatcher { sinks };

    for event in queued {
        let class = event.class();
        let commit_result = match event {
            QueuedEvent::User(e) => sinks.user.record(e),
            QueuedEvent::Channel(e) => sinks.channel.record(e),
            QueuedEvent::Substrate(e) => sinks.substrate.record(e),
            QueuedEvent::Moderation(e) => sinks.moderation.record(e),
        };
        match commit_result {
            Ok(()) => scope.record_committed(class),
            Err(commit_err) => {
                // Phase 3: rollback. Fire markers to sinks that
                // already committed (in reverse priority order).
                handle_rollback(&scope, &dispatcher, sinks, class, commit_err).await
                    .map_err(E::from)?;
                // Unreachable in practice — handle_rollback
                // returns the originating error on success;
                // unreachable!() would be wrong because the
                // error path above always returns. Drop through
                // to the final unreachable! below.
                unreachable!("handle_rollback always returns an error");
            }
        }
    }

    Ok(returned)
}

/// Generate a fresh [`CompositeOpId`] from the OS CSPRNG. Used
/// once per [`composite_audit`] scope.
fn generate_composite_op_id() -> CompositeOpId {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG must be available for composite_op_id generation");
    CompositeOpId::from_bytes(bytes)
}

/// Handle the rollback path after a commit failure. Fires
/// rollback markers to every sink class that committed before
/// the failure (deduplicated by class), in reverse
/// [`COMMIT_PRIORITY_ORDER`]. Always returns an Err — the
/// originating commit failure is the meaningful error;
/// rollback failures are escalated and reported via
/// [`CompositeAuditError::RollbackDispatchFailed`] (which
/// supersedes the originating commit failure since rollback
/// failure is more severe).
async fn handle_rollback(
    scope: &CompositeAuditScope,
    dispatcher: &AuditSinksDispatcher<'_, '_>,
    sinks: &crate::ingress::AuditSinks<'_>,
    failing_class: SinkKind,
    originating_err: AuditError,
) -> Result<(), CompositeAuditError> {
    let committed = scope.committed_snapshot();
    // Reverse priority order: rollback the most-recently-
    // committed first.
    let rollback_targets: Vec<SinkKind> = COMMIT_PRIORITY_ORDER
        .iter()
        .rev()
        .filter(|c| committed.contains(c))
        .copied()
        .collect();

    for target in rollback_targets {
        if let Err(rollback_err) =
            emit_rollback_marker(scope, dispatcher, target, failing_class)
        {
            // Rollback dispatch failed. Escalate to FallbackAuditSink.
            // record_composite_failure returns unit; if it
            // panics, we return InconsistencyUnrecoverable.
            let escalation_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sinks.fallback.record_composite_failure(
                    scope.trace_id,
                    scope.composite_op_id,
                    &committed[..],
                    &[failing_class],
                    std::time::SystemTime::now(),
                );
            }));
            return match escalation_result {
                Ok(()) => Err(CompositeAuditError::RollbackDispatchFailed {
                    class: target,
                    source: rollback_err,
                }),
                Err(_) => Err(CompositeAuditError::InconsistencyUnrecoverable),
            };
        }
    }

    // All rollback markers dispatched cleanly. Return the
    // originating commit failure.
    Err(CompositeAuditError::SinkCommitFailed {
        class: failing_class,
        source: originating_err,
    })
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

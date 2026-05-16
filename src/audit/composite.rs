// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.9 composite-audit rollback machinery.
//!
//! [`composite_audit`] wraps a multi-sink operation in commit-or-
//! rollback semantics. The op closure receives a
//! [`CompositeAuditScope`] and queues per-class events via
//! [`CompositeAuditScope::emit_user`] /
//! [`CompositeAuditScope::emit_channel`] /
//! [`CompositeAuditScope::emit_substrate`] /
//! [`CompositeAuditScope::emit_moderation`]. Events are NOT
//! delivered to sinks during the op — they accumulate in the
//! scope and `composite_audit` flushes them after the op returns.
//!
//! ## Commit / rollback discipline
//!
//! - **Op returns Err**: queued events dropped; the op's error
//!   is returned unchanged. No sink is touched.
//! - **Op returns Ok**: queued events committed to the operator-
//!   installed [`crate::ingress::AuditSinks`] in
//!   `COMMIT_PRIORITY_ORDER` (substrate → moderation → user →
//!   channel). Within each class, the op's emit-order is
//!   preserved.
//! - **A commit fails partway**: rollback markers fire to all
//!   sinks that already committed (deduplicated by class), in
//!   reverse priority order. The error returned is
//!   [`CompositeAuditError::SinkCommitFailed`].
//! - **A rollback marker dispatch itself fails**: escalates to
//!   [`crate::audit::FallbackAuditSink::record_composite_failure`].
//!   Returns [`CompositeAuditError::RollbackDispatchFailed`].
//! - **The fallback escalation panics**: catch_unwind catches
//!   the panic; returns
//!   [`CompositeAuditError::InconsistencyUnrecoverable`].
//!   Operators should treat this as substrate-fatal.
//!
//! ## Class-priority commit order (§4.9 interpretive moment)
//!
//! §4.9 doesn't pin the cross-class commit order verbatim. The
//! crate's choice — substrate first, then moderation, user,
//! channel — orders by privilege: substrate-class events are
//! the most-privileged and most-diagnostic-on-failure, so
//! committing them first surfaces failures earliest. Channel-
//! class commits last because channel events are typically
//! least security-sensitive (sync channel observability rather
//! than capability decisions).
//!
//! The rollback path fires markers in reverse order — most-
//! recently-committed first — so the sink whose commit completed
//! closest to the failure gets its rollback marker first.
//!
//! ## Per-process tracker (reserved)
//!
//! [`TRACKER_SHARDS`], [`TRACKER_GRACE_WINDOW_DEFAULT`], and
//! [`TRACKER_GRACE_WINDOW_MAX`] are reserved for a future
//! per-process composite-op-id tracker that detects op_id
//! collisions and GCs stale scopes. v0.1's [`composite_audit`]
//! generates a fresh 16-byte op_id from the OS CSPRNG per
//! scope; collision probability is negligible (2^-64 birthday
//! bound at ~4 billion concurrent scopes). The tracker lands
//! when operator deployments push that bound.

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
///
/// **Reserved for v0.2+ per-process collision-detection
/// tracker.** Not consumed by [`composite_audit`] in v0.1; the
/// v0.1 `composite_op_id` collision bound is the 2⁻⁶⁴
/// birthday-bound bet on 16 bytes from CSPRNG. The constant
/// ships now so the v0.2 tracker's shape is reserved without a
/// public-surface bump.
pub const TRACKER_SHARDS: usize = 16;

/// Default grace window for the composite-id tracker (§4.9).
///
/// **Reserved for v0.2+ per-process collision-detection
/// tracker.** See [`TRACKER_SHARDS`] for the broader posture.
/// Not consumed by [`composite_audit`] in v0.1.
pub const TRACKER_GRACE_WINDOW_DEFAULT: Duration = Duration::from_millis(100);

/// Hard cap on grace-window configuration (§4.9). Configurations
/// exceeding this are rejected at config-load time.
///
/// **Reserved for v0.2+ per-process collision-detection
/// tracker.** See [`TRACKER_SHARDS`] for the broader posture.
/// Not consumed by [`composite_audit`] in v0.1.
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
    /// `COMMIT_PRIORITY_ORDER`.
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
    /// `COMMIT_PRIORITY_ORDER` (stable within each class so
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
/// Emitted by [`composite_audit`]'s rollback path to every
/// sibling sink that already committed within a scope when a
/// later sink failed (crate-internal dispatch).
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
///    to the operator-installed sinks in `COMMIT_PRIORITY_ORDER`
///    (substrate → moderation → user → channel). Within each
///    class, the op's emit-order is preserved.
/// 4. If a commit fails partway: rollback markers fire to all
///    sinks that already committed (deduplicated by class), in
///    reverse `COMMIT_PRIORITY_ORDER`. The error returned is
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
/// # Emitting denial events
///
/// The op closure's `Err(e)` path **drops queued events without
/// rollback** (scenario 2 above). This is correct behavior — an
/// error before commit means no sink ever saw the events, so
/// there is nothing to roll back. But it also means an op
/// closure that returns `Err` to signal an application-level
/// denial will **lose** any denial event it queued.
///
/// For business-level denials that must commit their audit
/// emit, route the denial through the op's `Ok(R)` return
/// channel using a sum type — not `Err`. The
/// [`crate::authority`] bind pipeline uses this exact pattern:
///
/// ```text
/// enum BindOutcome<P> {
///     Success(P),
///     Denied { stage, reason },
/// }
///
/// let outcome: Result<BindOutcome<_>, MyError> = composite_audit(
///     trace_id,
///     sinks,
///     async |scope| {
///         if denial_predicate_fails {
///             // Queue the denial event BEFORE returning Ok(Denied).
///             // The Ok path commits queued events to sinks.
///             scope.emit_user(denial_event);
///             return Ok(BindOutcome::Denied { stage, reason });
///         }
///         // ... happy path ...
///         scope.emit_user(success_event);
///         Ok(BindOutcome::Success(bound_proof))
///     },
/// ).await;
/// ```
///
/// Returning `Err(MyError::Denied)` from the op closure would
/// drop the queued denial event — that path is reserved for
/// infrastructure failures (the op cannot construct an audit
/// event due to system state, etc.), not for application-level
/// denials. Operators writing custom composite ops should keep
/// this rule in mind: **`Err` drops events; commit-or-deny
/// outcomes flow through `Ok`**.
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
    // composite_op_id is generated fresh per scope. The
    // per-process tracker for op_id collisions / GC lands in a
    // future cycle (TRACKER_SHARDS / TRACKER_GRACE_WINDOW
    // constants are reserved).
    let composite_op_id = generate_composite_op_id();
    let scope = CompositeAuditScope::new_internal(trace_id, composite_op_id);

    // Step 1: run the op.
    let op_result = op(&scope).await;
    let returned = match op_result {
        Ok(r) => r,
        Err(e) => {
            // Op failed — drop queued events, return E unchanged.
            // No commit, no rollback (nothing committed).
            return Err(e);
        }
    };

    // Step 2: commit queued events in priority order.
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
                // Step 3: rollback. Fire markers to sinks that
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
/// `COMMIT_PRIORITY_ORDER`. Always returns an Err — the
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

    // ============================================================
    // §4.9 composite_audit / emit_rollback_marker tests.
    // ============================================================

    use crate::audit::bounded_string::BoundedString;
    use crate::audit::events::{
        ChannelAuditEvent, FallbackAuditEvent, ModerationAuditEvent, ModeratorRationale,
        SubstrateAuditEvent, UserAuditEvent, MAX_RATIONALE_LEN,
    };
    use crate::audit::sinks::{
        ChannelAuditSink, FallbackAuditSink, ModerationAuditSink, SubstrateAuditSink,
        UserAuditSink,
    };
    use crate::authority::predicate::BindOutcomeRepr;
    use crate::authority::ModerationCaseId;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex as StdMutex;

    /// Mock per-class sink that captures every event recorded
    /// and optionally fails on the Nth call.
    struct MockSink<E: Clone + Send + Sync + 'static> {
        captured: StdMutex<Vec<E>>,
        call_count: AtomicUsize,
        /// 1-indexed: Some(N) → fail on the Nth call. None → never fail.
        fail_on_call: Option<usize>,
    }

    impl<E: Clone + Send + Sync + 'static> MockSink<E> {
        fn new(fail_on_call: Option<usize>) -> Self {
            MockSink {
                captured: StdMutex::new(Vec::new()),
                call_count: AtomicUsize::new(0),
                fail_on_call,
            }
        }
        fn captured(&self) -> Vec<E> {
            self.captured.lock().unwrap().clone()
        }
        fn record_inner(&self, event: E) -> Result<(), AuditError> {
            let n = self.call_count.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            if Some(n) == self.fail_on_call {
                return Err(AuditError::Unavailable);
            }
            self.captured.lock().unwrap().push(event);
            Ok(())
        }
    }

    impl UserAuditSink for MockSink<UserAuditEvent> {
        fn record(&self, event: UserAuditEvent) -> Result<(), AuditError> {
            self.record_inner(event)
        }
    }
    impl ChannelAuditSink for MockSink<ChannelAuditEvent> {
        fn record(&self, event: ChannelAuditEvent) -> Result<(), AuditError> {
            self.record_inner(event)
        }
    }
    impl SubstrateAuditSink for MockSink<SubstrateAuditEvent> {
        fn record(&self, event: SubstrateAuditEvent) -> Result<(), AuditError> {
            self.record_inner(event)
        }
    }
    impl ModerationAuditSink for MockSink<ModerationAuditEvent> {
        fn record(&self, event: ModerationAuditEvent) -> Result<(), AuditError> {
            self.record_inner(event)
        }
    }

    /// Captured composite-failure-call shape.
    type FallbackCapture = (TraceId, CompositeOpId, Vec<SinkKind>, Vec<SinkKind>);

    /// Mock fallback sink. Captures `record_composite_failure`
    /// calls; optionally panics on call (for the
    /// InconsistencyUnrecoverable test).
    struct MockFallback {
        captured: StdMutex<Vec<FallbackCapture>>,
        panic_on_call: bool,
    }

    impl MockFallback {
        fn new(panic_on_call: bool) -> Self {
            MockFallback {
                captured: StdMutex::new(Vec::new()),
                panic_on_call,
            }
        }
        fn captured_count(&self) -> usize {
            self.captured.lock().unwrap().len()
        }
    }

    impl FallbackAuditSink for MockFallback {
        fn record_panic(
            &self,
            _sink: SinkKind,
            _trace_id: TraceId,
            _capability: crate::authority::capability::CapabilityKind,
            _at: std::time::SystemTime,
        ) {
        }
        fn record_composite_failure(
            &self,
            trace_id: TraceId,
            composite_op_id: CompositeOpId,
            sinks_committed: &[SinkKind],
            sinks_failed: &[SinkKind],
            _at: std::time::SystemTime,
        ) {
            if self.panic_on_call {
                panic!("MockFallback configured to panic on record_composite_failure");
            }
            self.captured.lock().unwrap().push((
                trace_id,
                composite_op_id,
                sinks_committed.to_vec(),
                sinks_failed.to_vec(),
            ));
        }
        fn record_event(&self, _event: FallbackAuditEvent) {}
    }

    fn sample_did() -> crate::proto::Did {
        crate::proto::Did::new("did:plc:phase7btest").unwrap()
    }

    fn sample_target_repr() -> crate::target::TargetRepresentation {
        crate::target::TargetRepresentation::structural_only(
            crate::target::StructuralRepresentation::Resource {
                did: sample_did(),
                nsid: crate::Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            },
        )
    }

    fn sample_service_identity() -> crate::identity::ServiceIdentity {
        crate::identity::ServiceIdentity::new_internal(
            sample_did(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn sample_user_event() -> UserAuditEvent {
        UserAuditEvent::CapabilityBound {
            trace_id: TraceId::from_bytes([0xA1; 16]),
            requester: sample_did(),
            subject_repr: sample_target_repr(),
            capability: crate::authority::capability::CapabilityKind::ViewPrivate,
            outcome: BindOutcomeRepr::Success,
            attribution: crate::ingress::AttributionChain::empty(),
            at: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    fn sample_channel_event() -> ChannelAuditEvent {
        ChannelAuditEvent::ChannelClosed {
            trace_id: TraceId::from_bytes([0xC1; 16]),
            peer: sample_service_identity(),
            session_digest: crate::identity::SessionDigest::from_bytes([0u8; 32]),
            cause: crate::audit::events::ChannelCloseCause::CleanClose,
            at: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    fn sample_substrate_event() -> SubstrateAuditEvent {
        SubstrateAuditEvent::ScopeBound {
            trace_id: TraceId::from_bytes([0x51; 16]),
            service: sample_service_identity(),
            scope_repr: sample_target_repr(),
            capability: crate::authority::capability::CapabilityKind::ScanShard,
            outcome: BindOutcomeRepr::Success,
            at: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    fn sample_moderation_event() -> ModerationAuditEvent {
        ModerationAuditEvent::ModeratorInspected {
            trace_id: TraceId::from_bytes([0xD1; 16]),
            moderator: sample_did(),
            case: ModerationCaseId::from_bytes([0u8; 16]),
            target_repr: sample_target_repr(),
            rationale: ModeratorRationale::Declared(
                BoundedString::<MAX_RATIONALE_LEN>::new("test").unwrap(),
            ),
            at: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    /// Operator-side error type that embeds CompositeAuditError
    /// via #[from]. Mirrors the rustdoc'd pattern.
    #[derive(Debug)]
    enum TestError {
        Composite(CompositeAuditError),
        OpSpecific(&'static str),
    }
    impl From<CompositeAuditError> for TestError {
        fn from(e: CompositeAuditError) -> Self {
            TestError::Composite(e)
        }
    }

    fn build_sinks<'a>(
        user: &'a MockSink<UserAuditEvent>,
        channel: &'a MockSink<ChannelAuditEvent>,
        substrate: &'a MockSink<SubstrateAuditEvent>,
        moderation: &'a MockSink<ModerationAuditEvent>,
        fallback: &'a MockFallback,
    ) -> crate::ingress::AuditSinks<'a> {
        // Composite-audit tests don't exercise the inspection
        // queue (it's outside composite-rollback semantics per
        // §6.7) or compute session digests. Use no-op defaults
        // to satisfy the AuditSinks shape.
        static NO_INSPECTION: crate::authority::NoInspectionNotifications =
            crate::authority::NoInspectionNotifications;
        static NO_CORRELATION_KEY: crate::identity::CorrelationKey =
            crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        crate::ingress::AuditSinks {
            user,
            channel,
            substrate,
            moderation,
            fallback,
            inspection_queue: &NO_INSPECTION,
            correlation_key: &NO_CORRELATION_KEY,
        }
    }

    /// Scenario 1 — happy path: op returns Ok, all sinks
    /// commit cleanly, no rollback marker fires.
    #[tokio::test]
    async fn happy_path_commits_all_queued_events() {
        let user = MockSink::<UserAuditEvent>::new(None);
        let channel = MockSink::<ChannelAuditEvent>::new(None);
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(false);
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let result: Result<u32, TestError> = composite_audit(
            TraceId::from_bytes([0xFF; 16]),
            &sinks,
            async |scope| {
                scope.emit_user(sample_user_event());
                scope.emit_channel(sample_channel_event());
                scope.emit_substrate(sample_substrate_event());
                scope.emit_moderation(sample_moderation_event());
                Ok(42)
            },
        )
        .await;
        assert!(matches!(result, Ok(42)));
        assert_eq!(user.captured().len(), 1);
        assert_eq!(channel.captured().len(), 1);
        assert_eq!(substrate.captured().len(), 1);
        assert_eq!(moderation.captured().len(), 1);
        assert_eq!(fallback.captured_count(), 0);
    }

    /// Scenario 2 — op returns Err before any emit: queued
    /// events dropped, no sink touched, error returned
    /// unchanged.
    #[tokio::test]
    async fn op_failure_returns_op_error_unchanged_no_emit() {
        let user = MockSink::<UserAuditEvent>::new(None);
        let channel = MockSink::<ChannelAuditEvent>::new(None);
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(false);
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let result: Result<u32, TestError> = composite_audit(
            TraceId::from_bytes([0; 16]),
            &sinks,
            async |scope| {
                scope.emit_user(sample_user_event());
                Err(TestError::OpSpecific("op rejected"))
            },
        )
        .await;
        assert!(matches!(result, Err(TestError::OpSpecific("op rejected"))));
        assert!(user.captured().is_empty());
        assert!(channel.captured().is_empty());
        assert_eq!(fallback.captured_count(), 0);
    }

    /// Scenario 3 — single-class commit then sibling failure:
    /// op queues user + channel. After op returns Ok, user
    /// commits cleanly; channel commit fails. Rollback marker
    /// fires to user sink.
    #[tokio::test]
    async fn channel_commit_failure_rolls_back_user() {
        let user = MockSink::<UserAuditEvent>::new(None);
        // Channel fails on its first call (the operator's event,
        // before any rollback marker would have a chance to fire).
        let channel = MockSink::<ChannelAuditEvent>::new(Some(1));
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(false);
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let result: Result<(), TestError> = composite_audit(
            TraceId::from_bytes([0x33; 16]),
            &sinks,
            async |scope| {
                scope.emit_user(sample_user_event());
                scope.emit_channel(sample_channel_event());
                Ok(())
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(TestError::Composite(CompositeAuditError::SinkCommitFailed {
                class: SinkKind::Channel,
                ..
            }))
        ));
        // User sink received the operator's event AND the
        // rollback marker.
        let user_events = user.captured();
        assert_eq!(user_events.len(), 2, "user sink should have op event + rollback marker");
        assert!(matches!(
            user_events[1],
            UserAuditEvent::CompositeRollbackMarker { failing_sink: SinkKind::Channel, .. }
        ));
        assert_eq!(fallback.captured_count(), 0);
    }

    /// Scenario 4 — multi-class success then last-class
    /// failure. Per COMMIT_PRIORITY_ORDER the channel sink
    /// commits LAST; making it fail leaves substrate +
    /// moderation + user already committed. All three get
    /// rollback markers in reverse order (user → moderation →
    /// substrate).
    #[tokio::test]
    async fn channel_failure_after_three_commits_rolls_back_three() {
        let user = MockSink::<UserAuditEvent>::new(None);
        let channel = MockSink::<ChannelAuditEvent>::new(Some(1));
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(false);
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let result: Result<(), TestError> = composite_audit(
            TraceId::from_bytes([0x44; 16]),
            &sinks,
            async |scope| {
                scope.emit_user(sample_user_event());
                scope.emit_channel(sample_channel_event());
                scope.emit_substrate(sample_substrate_event());
                scope.emit_moderation(sample_moderation_event());
                Ok(())
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(TestError::Composite(CompositeAuditError::SinkCommitFailed {
                class: SinkKind::Channel,
                ..
            }))
        ));
        // Each pre-channel sink got the op event + a rollback
        // marker.
        assert_eq!(user.captured().len(), 2);
        assert_eq!(substrate.captured().len(), 2);
        assert_eq!(moderation.captured().len(), 2);
        // Channel only saw its one (failing) op-event call.
        assert_eq!(channel.captured().len(), 0); // failed, not captured
        assert_eq!(fallback.captured_count(), 0);
    }

    /// Scenario 5 — rollback dispatch itself fails.
    /// Channel commit fails AND the user-sink's rollback
    /// marker dispatch fails. Escalation to fallback sink
    /// fires (record_composite_failure called).
    #[tokio::test]
    async fn rollback_dispatch_failure_escalates_to_fallback() {
        // User: succeeds on the op event (call 1) but fails on
        // the rollback marker (call 2).
        let user = MockSink::<UserAuditEvent>::new(Some(2));
        // Channel: fails on its op event (call 1) → triggers rollback.
        let channel = MockSink::<ChannelAuditEvent>::new(Some(1));
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(false);
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let result: Result<(), TestError> = composite_audit(
            TraceId::from_bytes([0x55; 16]),
            &sinks,
            async |scope| {
                scope.emit_user(sample_user_event());
                scope.emit_channel(sample_channel_event());
                Ok(())
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(TestError::Composite(CompositeAuditError::RollbackDispatchFailed {
                class: SinkKind::User,
                ..
            }))
        ));
        // Fallback fired exactly once.
        assert_eq!(fallback.captured_count(), 1);
    }

    /// Scenario 6 — both rollback AND escalation fail. Channel
    /// commit fails → user rollback fails → fallback panics.
    /// Returns InconsistencyUnrecoverable; no panic propagates.
    #[tokio::test]
    async fn fallback_panic_returns_inconsistency_unrecoverable() {
        let user = MockSink::<UserAuditEvent>::new(Some(2));
        let channel = MockSink::<ChannelAuditEvent>::new(Some(1));
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(true); // panic on call
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let result: Result<(), TestError> = composite_audit(
            TraceId::from_bytes([0x66; 16]),
            &sinks,
            async |scope| {
                scope.emit_user(sample_user_event());
                scope.emit_channel(sample_channel_event());
                Ok(())
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(TestError::Composite(CompositeAuditError::InconsistencyUnrecoverable))
        ));
    }

    /// Scenario 7 — class-priority commit ordering.
    /// Op queues channel + user + substrate + moderation in
    /// that order. After commit, examining capture timestamps
    /// (or just commit-call order via fail_on_call placement)
    /// confirms substrate → moderation → user → channel order.
    /// Approach: make user sink fail on call 1; expect
    /// substrate + moderation already captured (committed before
    /// user) but channel NOT captured (queued after user in
    /// priority).
    #[tokio::test]
    async fn class_priority_ordering_substrate_first_channel_last() {
        let user = MockSink::<UserAuditEvent>::new(Some(1));
        let channel = MockSink::<ChannelAuditEvent>::new(None);
        let substrate = MockSink::<SubstrateAuditEvent>::new(None);
        let moderation = MockSink::<ModerationAuditEvent>::new(None);
        let fallback = MockFallback::new(false);
        let sinks = build_sinks(&user, &channel, &substrate, &moderation, &fallback);

        let _result: Result<(), TestError> = composite_audit(
            TraceId::from_bytes([0x77; 16]),
            &sinks,
            async |scope| {
                // Emit in NON-priority order.
                scope.emit_channel(sample_channel_event());
                scope.emit_user(sample_user_event());
                scope.emit_substrate(sample_substrate_event());
                scope.emit_moderation(sample_moderation_event());
                Ok(())
            },
        )
        .await;
        // User was 3rd in priority order (substrate=1,
        // moderation=2, user=3, channel=4). Failing on user's
        // call means substrate + moderation already committed,
        // channel never reached.
        assert_eq!(substrate.captured().len(), 2, "substrate: op event + rollback marker");
        assert_eq!(moderation.captured().len(), 2, "moderation: op event + rollback marker");
        // User failed on call 1 — captured nothing. Rollback
        // markers do NOT fire to the failing sink (only to
        // sinks that successfully committed before the failure).
        assert_eq!(user.captured().len(), 0, "user: failed on op event; not in committed-set; no rollback marker");
        // Channel never reached commit (queued last in priority
        // and the loop short-circuits after the user failure).
        assert_eq!(channel.captured().len(), 0, "channel queued last in priority order; not reached");
    }
}

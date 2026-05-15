// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.9 audit-sink trait surfaces, panic-guard machinery,
//! [`FallbackAuditSink`] contract.

use std::panic::{AssertUnwindSafe, UnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

use super::events::{
    ChannelAuditEvent, FallbackAuditEvent, ModerationAuditEvent, SubstrateAuditEvent,
    UserAuditEvent,
};

/// Audit-sink failure cases (§4.9).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuditError {
    /// Sink is unavailable (e.g., terminated by panic, backend
    /// down).
    #[error("audit sink unavailable")]
    Unavailable,
    /// Sink's internal buffer is full; back-pressure signal.
    #[error("audit buffer rejected event")]
    BufferRejected,
}

/// Discriminator for the four audit-sink channels (§4.9).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkKind {
    /// User-class.
    User,
    /// Channel-class.
    Channel,
    /// Substrate-class.
    Substrate,
    /// Moderation-class.
    Moderation,
}

// ============================================================
// The four channel sink traits.
// ============================================================

/// User-class audit sink (§4.9).
///
/// Implementations **must not block**. Sinks performing I/O must
/// buffer internally and flush asynchronously; the synchronous
/// `record()` call enqueues and returns. When the internal buffer
/// is full, return [`AuditError::BufferRejected`] — this is the
/// designed back-pressure channel and substrate `bind` paths
/// treat it as fail-closed (§4.3 / §4.9 A4 invariant).
pub trait UserAuditSink: Send + Sync {
    /// Record a user-class event.
    fn record(&self, event: UserAuditEvent) -> Result<(), AuditError>;
}

/// Channel-class audit sink (§4.9).
pub trait ChannelAuditSink: Send + Sync {
    /// Record a channel-class event.
    fn record(&self, event: ChannelAuditEvent) -> Result<(), AuditError>;
}

/// Substrate-class audit sink (§4.9).
pub trait SubstrateAuditSink: Send + Sync {
    /// Record a substrate-class event.
    fn record(&self, event: SubstrateAuditEvent) -> Result<(), AuditError>;
}

/// Moderation-class audit sink (§4.9).
pub trait ModerationAuditSink: Send + Sync {
    /// Record a moderation-class event.
    fn record(&self, event: ModerationAuditEvent) -> Result<(), AuditError>;
}

/// Fallback sink for sink-panic / composite-failure events
/// (§4.9 / §6.6).
///
/// **Must not panic.** If it does, the substrate logs to stderr
/// and aborts the process.
///
/// The two argument-shape methods ([`Self::record_panic`] and
/// [`Self::record_composite_failure`]) take an explicit `at:
/// SystemTime` so the substrate's emission timestamp matches what
/// the variants record per §6.1's universal `at` rule. Sink
/// implementers preferring to receive the constructed event
/// directly use [`Self::record_event`].
pub trait FallbackAuditSink: Send + Sync {
    /// Record a sink panic.
    fn record_panic(
        &self,
        sink: SinkKind,
        trace_id: crate::identity::TraceId,
        capability: crate::authority::capability::CapabilityKind,
        at: std::time::SystemTime,
    );

    /// Record a composite-audit failure.
    fn record_composite_failure(
        &self,
        trace_id: crate::identity::TraceId,
        composite_op_id: super::composite::CompositeOpId,
        sinks_committed: &[SinkKind],
        sinks_failed: &[SinkKind],
        at: std::time::SystemTime,
    );

    /// Generic record entry: helpful for tests and
    /// dispatch-by-event wrappers.
    fn record_event(&self, event: FallbackAuditEvent);
}

// ============================================================
// Panic-guard machinery.
// ============================================================

/// Marker indicating a [`std::panic::catch_unwind`] caught a
/// panic (§4.3 / §4.9).
///
/// Carried in [`SinkPanicGuard::call`]'s `Err` variant. Operator
/// code generally does not pattern-match on this — the wrapper
/// types ([`TerminatedSinkGuard`]) translate it to
/// [`AuditError::Unavailable`].
#[derive(Debug, Clone, Copy)]
pub struct Panicked;

/// Catches panics around a sink call so they translate to
/// fail-closed (§4.3).
pub struct SinkPanicGuard;

impl SinkPanicGuard {
    /// Run `f` under [`std::panic::catch_unwind`]; return
    /// [`Panicked`] on panic.
    ///
    /// # Errors
    ///
    /// Returns [`Panicked`] if `f` panicked.
    pub fn call<F, T>(f: F) -> Result<T, Panicked>
    where
        F: FnOnce() -> T + UnwindSafe,
    {
        std::panic::catch_unwind(AssertUnwindSafe(f)).map_err(|_| Panicked)
    }
}

/// Crash-recovery wrapper around a [`UserAuditSink`] (§4.3 /
/// §4.9).
///
/// On first sink-record panic, the wrapper flips its terminated
/// flag and rejects all subsequent records with
/// [`AuditError::Unavailable`]. Operators wrap every production
/// sink in a `TerminatedSinkGuard` so a panicked sink doesn't
/// continue running against corrupt internal state.
///
/// Phase 1 ships the [`UserAuditSink`] wrapper; parallel
/// wrappers for the other three channel sinks land in Phase 4
/// (mechanical parallel). The pattern is identical — see
/// CHAINLINKS #9.
pub struct TerminatedSinkGuard<S> {
    inner: S,
    terminated: AtomicBool,
}

impl<S> TerminatedSinkGuard<S> {
    /// Wrap a sink with crash-recovery semantics.
    #[must_use]
    pub fn new(inner: S) -> Self {
        TerminatedSinkGuard {
            inner,
            terminated: AtomicBool::new(false),
        }
    }
}

impl<S> UserAuditSink for TerminatedSinkGuard<S>
where
    S: UserAuditSink + std::panic::RefUnwindSafe + Send + Sync,
{
    fn record(&self, event: UserAuditEvent) -> Result<(), AuditError> {
        if self.terminated.load(Ordering::Acquire) {
            return Err(AuditError::Unavailable);
        }
        match SinkPanicGuard::call(|| self.inner.record(event)) {
            Ok(result) => result,
            Err(Panicked) => {
                self.terminated.store(true, Ordering::Release);
                Err(AuditError::Unavailable)
            }
        }
    }
}

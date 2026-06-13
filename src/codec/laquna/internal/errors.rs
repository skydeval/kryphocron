// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! Decode-time failure variants and the conditions that produce them.
//!
//! Returned by `decode`; see that function for the order in which these
//! conditions are checked.

/// Error returned by `decode` when an artifact cannot be recovered.
///
/// A conforming decoder keeps these variants distinct rather than collapsing them
/// into a single opaque error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input is shorter than the minimum artifact length (version byte + slug).
    InputTooShort,
    /// Leading version byte is not the one this version of the format accepts.
    InvalidVersion(u8),
    /// The recovered bytes did not validate — typically a wrong seed, a wrong
    /// slug, or corruption. Carries no detail by design.
    DecompressionFailed,
    /// The supplied seed was empty. An empty seed cannot satisfy the per-record
    /// uniqueness requirement and is rejected before any other processing.
    EmptySeed,
}
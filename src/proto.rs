//! Re-exports of validated AT Protocol primitive types.
//!
//! Phase 1 shipped these as **local placeholders** (CHAINLINKS #3).
//! Phase 2 (§5 lexicon strategy) closes that chainlink: the real
//! validated newtypes live in `proto-blue-syntax` /
//! `proto-blue-lex-data`, re-exported here through
//! [`kryphocron-lexicons`](::kryphocron_lexicons) so the kryphocron
//! crate has a single canonical home for these identifiers.
//!
//! ## Why re-export through `kryphocron-lexicons`
//!
//! The lexicon companion crate already depends on the proto-blue
//! family (its build script consumes `proto-blue-lexicon` for
//! [`LexiconDoc`](kryphocron_lexicons::LexiconDoc) parsing in the
//! §5.4 structural-validation pass). Routing kryphocron's
//! identifier dependency through the same surface keeps both
//! crates pinned to the same proto-blue versions automatically —
//! one upgrade point, no per-crate drift.
//!
//! ## Name compatibility
//!
//! Phase 1's [`Rkey`] type is re-exported as
//! [`kryphocron_lexicons::RecordKey`]. The Phase 1 public surface
//! used the shorter spelling; this module ships a `pub use ... as`
//! alias so existing call sites continue to resolve.
//!
//! ## Validation behavior
//!
//! Unlike the Phase 1 placeholders (which accepted any non-empty
//! UTF-8), the real validators enforce the ATProto-spec grammar:
//!
//! - [`Did`] requires the `did:<method>:<id>` format.
//! - [`Nsid`] requires the dotted-segment grammar (minimum 3
//!   segments, ASCII identifier characters).
//! - [`AtUri`] requires the `at://` scheme.
//! - [`Cid`] requires DASL-compliant codec/hash codes when
//!   parsed from bytes.
//!
//! See `kryphocron-lexicons` and the proto-blue crates for the
//! exact validation rules each constructor enforces.

pub use kryphocron_lexicons::{
    AtUri, BlobRef, Cid, CidError, Datetime, Did, Handle, Nsid, RecordKey,
    Tid, UnknownNsid,
};

/// Phase 1 compatibility alias for [`RecordKey`].
///
/// The Phase 1 public surface exported `Rkey`; the upstream name
/// is `RecordKey`. The alias keeps the kryphocron crate's
/// re-export shape stable across the Phase 2 swap.
pub use kryphocron_lexicons::RecordKey as Rkey;

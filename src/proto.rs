// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of validated AT Protocol primitive types.
//!
//! The real validated newtypes live in `proto-blue-syntax` /
//! `proto-blue-lex-data`, re-exported here through
//! [`kryphocron-lexicons`](::kryphocron_lexicons) so the kryphocron
//! crate has a single canonical home for these identifiers (§5
//! lexicon strategy).
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
//! The [`Rkey`] type is re-exported as
//! [`kryphocron_lexicons::RecordKey`]. Earlier internal drafts of
//! the public surface used the shorter spelling; this module ships
//! a `pub use ... as` alias so existing call sites continue to
//! resolve.
//!
//! ## Validation behavior
//!
//! The validators enforce the ATProto-spec grammar:
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

/// Compatibility alias for [`RecordKey`].
///
/// Earlier internal drafts of the public surface exported `Rkey`;
/// the upstream name is `RecordKey`. The alias keeps the kryphocron
/// crate's re-export shape stable across the lexicon-crate swap.
pub use kryphocron_lexicons::RecordKey as Rkey;

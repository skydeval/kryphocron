// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! The three component stream generators whose outputs are folded into the mask.
//!
//! Each submodule exposes a generator with the same shape — `new(&Material)` then
//! `produce(length)` — so the consumer in `lib.rs` treats them uniformly and never sees
//! what each one does internally. The streams are labelled `a`, `b`, `c` after the
//! component-stream letters in the format; the labels name a role, not a primitive.

pub(crate) mod anchor;
pub(crate) mod extendable;
pub(crate) mod network;
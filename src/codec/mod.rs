// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Built-in [`ContentCodec`](crate::encryption::ContentCodec)
//! implementations shipped with the substrate (rev 3 §3.7).
//!
//! `laquna` is the default at-rest content codec — kryphocron deployments
//! encode private-tier records at rest via it by default (the constitutional
//! encoding-at-default floor). This `codec` parent module is the namespace
//! for built-in codecs; a future cycle adding another built-in codec lands it
//! at `kryphocron::codec::<name>`.

pub mod laquna;

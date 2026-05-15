// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Algorithm-tagged signature byte container (§4.8).

use crate::identity::SignatureAlgorithm;

/// Ed25519-sized signature with an explicit algorithm tag (§4.8).
///
/// The byte length is fixed at 64 to match Ed25519. When future
/// algorithm variants ship that require different byte lengths,
/// the [`SignatureAlgorithm`] enum and this struct evolve in
/// lockstep. `#[non_exhaustive]` on the algorithm enum makes the
/// growth additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ClaimSignature {
    /// Algorithm under which `bytes` is interpreted.
    pub algorithm: SignatureAlgorithm,
    /// Raw signature bytes (Ed25519: 64 bytes).
    pub bytes: [u8; 64],
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! Keying-material derivation.
//!
//! Turns the caller's `(seed, slug)` into the opaque per-generator material that seeds
//! each of the three component streams in the mask pipeline. See `lib.rs` for how the
//! material flows into the generators.
//!
//! Each stream draws from a distinct derivation context, so the three materials are
//! uncorrelated even though they share the same `(seed, slug)` inputs.

/// Derivation context for the anchor stream's material.
const ANCHOR_CONTEXT: &[u8] = b"laquna/v0.2/stream-A";
/// Derivation context for the extendable stream's material.
const EXTENDABLE_CONTEXT: &[u8] = b"laquna/v0.2/stream-B";
/// Derivation context for the network stream's parameter material.
const NETWORK_CONTEXT: &[u8] = b"laquna/v0.2/stream-C-params";

/// Opaque keying material for the three component stream generators.
///
/// Constructed only by [`derive`]; the per-stream material is read back through the
/// crate-internal accessors.
pub struct Material {
    anchor: [u8; 32],
    extendable: [u8; 32],
    network_params: [u8; 32],
}

/// Derive the keying material for all three component streams from `seed` and `slug`.
pub fn derive(seed: &[u8], slug: &[u8; 32]) -> Material {
    Material {
        anchor: expand(seed, slug, ANCHOR_CONTEXT),
        extendable: expand(seed, slug, EXTENDABLE_CONTEXT),
        network_params: expand(seed, slug, NETWORK_CONTEXT),
    }
}

impl Material {
    /// Material seeding the anchor stream (component stream A).
    pub(crate) fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }

    /// Material seeding the extendable stream (component stream B).
    pub(crate) fn extendable(&self) -> &[u8; 32] {
        &self.extendable
    }

    /// Material from which the network stream (component stream C) derives its
    /// parameters and initial state.
    pub(crate) fn network_params(&self) -> &[u8; 32] {
        &self.network_params
    }
}

/// Expand 32 bytes of material from `(seed, slug)` under one derivation context.
///
/// The seed supplies the input keying material and the slug the salt. The two MUST NOT
/// be swapped: the seed carries the per-record entropy, the slug the batch context.
fn expand(seed: &[u8], slug: &[u8; 32], context: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let derivation = Hkdf::<Sha256>::new(Some(&slug[..]), seed);
    let mut out = [0u8; 32];
    derivation
        .expand(context, &mut out)
        .expect("a 32-byte expansion is always within the derivation's output bound");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed test seed and slug. The expected materials below were computed by an
    /// independent from-scratch reference implementation of the standard derivation,
    /// so the test cross-checks this code against an outside source of truth rather
    /// than against itself.
    const TEST_SEED: &[u8] =
        b"did:plc:7iza6de2dwap2sbkpav7c6c6||3laqlxv2k7s2y||laquna/v0.2";
    const TEST_SLUG: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    const EXPECT_ANCHOR: &str =
        "36167982bc04db965b2ac80a4ec72285bc2ad7f8e44f1ce284969e9acd01f7a0";
    const EXPECT_EXTENDABLE: &str =
        "6934cb5853df7f420dfaed553181fbd4502ece994f30624faa222f3a24ca4506";
    const EXPECT_NETWORK: &str =
        "792c9e70e9a74e63513645efac7992accd298be9a35fc9d1ea519e5ce1d5f5bb";

    fn expect(hex_str: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut out).unwrap();
        out
    }

    #[test]
    fn matches_independent_reference() {
        let m = derive(TEST_SEED, &TEST_SLUG);
        assert_eq!(m.anchor(), &expect(EXPECT_ANCHOR));
        assert_eq!(m.extendable(), &expect(EXPECT_EXTENDABLE));
        assert_eq!(m.network_params(), &expect(EXPECT_NETWORK));
    }

    #[test]
    fn same_inputs_are_identical() {
        let a = derive(TEST_SEED, &TEST_SLUG);
        let b = derive(TEST_SEED, &TEST_SLUG);
        assert_eq!(a.anchor(), b.anchor());
        assert_eq!(a.extendable(), b.extendable());
        assert_eq!(a.network_params(), b.network_params());
    }

    #[test]
    fn distinct_seeds_differ() {
        let a = derive(TEST_SEED, &TEST_SLUG);
        let b = derive(b"a different per-record seed", &TEST_SLUG);
        assert_ne!(a.anchor(), b.anchor());
        assert_ne!(a.extendable(), b.extendable());
        assert_ne!(a.network_params(), b.network_params());
    }

    #[test]
    fn distinct_slugs_differ() {
        let other_slug = [0xa5u8; 32];
        let a = derive(TEST_SEED, &TEST_SLUG);
        let b = derive(TEST_SEED, &other_slug);
        assert_ne!(a.anchor(), b.anchor());
        assert_ne!(a.extendable(), b.extendable());
        assert_ne!(a.network_params(), b.network_params());
    }

    /// The three contexts are distinct, so the three materials differ from one another
    /// even within a single derivation.
    #[test]
    fn three_materials_are_distinct() {
        let m = derive(TEST_SEED, &TEST_SLUG);
        assert_ne!(m.anchor(), m.extendable());
        assert_ne!(m.anchor(), m.network_params());
        assert_ne!(m.extendable(), m.network_params());
    }
}
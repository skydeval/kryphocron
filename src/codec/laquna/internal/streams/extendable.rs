// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! Extendable stream generator (component stream B).
//!
//! A second independent contribution to the mask, decorrelated from the anchor by its
//! distinct derivation context. See `lib.rs` for how this stream is consumed.

use alloc::{vec, vec::Vec};

use super::super::materials::Material;

/// Generator for the extendable stream.
pub(crate) struct ExtendableGenerator {
    reader: blake3::OutputReader,
}

impl ExtendableGenerator {
    /// Build a generator keyed by the extendable material, positioned at the start.
    pub(crate) fn new(material: &Material) -> Self {
        let reader = blake3::Hasher::new_keyed(material.extendable()).finalize_xof();
        ExtendableGenerator { reader }
    }

    /// Emit the next `length` bytes of the extendable stream.
    pub(crate) fn produce(&mut self, length: usize) -> Vec<u8> {
        let mut out = vec![0u8; length];
        self.reader.fill(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::materials::derive;

    const SEED: &[u8] =
        b"did:plc:7iza6de2dwap2sbkpav7c6c6||3laqlxv2k7s2y||laquna/v0.2";
    const SLUG: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// Independently computed (an outside reference implementation) first 64 bytes.
    const EXPECT_FIRST_64: &str = "07b62afb7755c2ecb395d2e83b3ba26dcd1ce656da29e20e14e18497571e64309b64e13bf14e9268c7531e6674a8ce5c279fb516e58eef55d524febedba6fe16";

    fn expect(hex_str: &str) -> Vec<u8> {
        let mut out = vec![0u8; hex_str.len() / 2];
        hex::decode_to_slice(hex_str, &mut out).unwrap();
        out
    }

    #[test]
    fn first_bytes_match_reference() {
        let m = derive(SEED, &SLUG);
        let bytes = ExtendableGenerator::new(&m).produce(64);
        assert_eq!(bytes, expect(EXPECT_FIRST_64));
    }

    #[test]
    fn deterministic_for_same_material() {
        let m = derive(SEED, &SLUG);
        let a = ExtendableGenerator::new(&m).produce(128);
        let b = ExtendableGenerator::new(&m).produce(128);
        assert_eq!(a, b);
    }

    #[test]
    fn differs_for_different_material() {
        let a = ExtendableGenerator::new(&derive(SEED, &SLUG)).produce(128);
        let b = ExtendableGenerator::new(&derive(b"a different seed", &SLUG)).produce(128);
        assert_ne!(a, b);
    }

    #[test]
    fn length_matches_request() {
        let m = derive(SEED, &SLUG);
        for len in [0usize, 1, 63, 64, 65, 1000] {
            assert_eq!(ExtendableGenerator::new(&m).produce(len).len(), len);
        }
    }

    /// Producing in two calls continues the stream, matching one larger call.
    #[test]
    fn incremental_matches_single() {
        let m = derive(SEED, &SLUG);
        let single = ExtendableGenerator::new(&m).produce(100);
        let mut split = ExtendableGenerator::new(&m);
        let mut joined = split.produce(64);
        joined.extend_from_slice(&split.produce(36));
        assert_eq!(single, joined);
    }
}
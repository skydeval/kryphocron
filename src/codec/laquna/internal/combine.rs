// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! Mask assembly.
//!
//! Folds the three component streams into the single mask that is XOR'd against the
//! compressed payload, and provides the byte-local XOR that applies a mask to a buffer
//! in either direction. Output position `i` depends only on the three inputs at `i`.

use alloc::vec::Vec;

/// Fold the three equal-length component streams into the final mask.
///
/// At each position: fold the first two together, rotate that within the byte by an
/// amount taken from the third stream, then fold the third in. The data-dependent
/// rotation is what stops a reader who has all three streams from recovering the input
/// with a plain three-way fold.
pub(crate) fn mix(stream_a: &[u8], stream_b: &[u8], stream_c: &[u8]) -> Vec<u8> {
    debug_assert_eq!(stream_a.len(), stream_b.len());
    debug_assert_eq!(stream_a.len(), stream_c.len());

    stream_a
        .iter()
        .zip(stream_b)
        .zip(stream_c)
        .map(|((&a, &b), &c)| {
            let folded = a ^ b;
            folded.rotate_left((c % 8) as u32) ^ c
        })
        .collect()
}

/// XOR two equal-length buffers into a fresh buffer. Self-inverse, so the same routine
/// serves both the encode and decode directions.
pub(crate) fn xor_buffers(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    lhs.iter().zip(rhs).map(|(&a, &b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-computed example, independent of the implementation.
    ///
    /// - i=0: (0x00^0x00) rotl 0 ^ 0x00 = 0x00
    /// - i=1: (0xff^0x00) rotl 1 ^ 0x01 = 0xff ^ 0x01 = 0xfe
    /// - i=2: (0x12^0x34) rotl 0 ^ 0x08 = 0x26 ^ 0x08 = 0x2e
    #[test]
    fn mix_matches_hand_computed() {
        let a = [0x00u8, 0xff, 0x12];
        let b = [0x00u8, 0x00, 0x34];
        let c = [0x00u8, 0x01, 0x08];
        assert_eq!(mix(&a, &b, &c), [0x00u8, 0xfe, 0x2e]);
    }

    /// The rotation is a within-byte bit rotation: 0x81 (1000_0001) rotated left by 1
    /// is 0x03 (0000_0011), then XOR 0x01 gives 0x02.
    #[test]
    fn mix_rotation_is_within_byte() {
        assert_eq!(mix(&[0x81], &[0x00], &[0x01]), [0x02]);
    }

    /// Cross-check the fold against an independent reference for the real streams of a
    /// fixed test material (the same first-64-byte values the stream tests pin).
    #[test]
    fn mix_matches_reference_streams() {
        let a = hex("3d44a1a4926b14e83ca7ae4c53eb0744ab32d76b1511ca3ae1374c5586a439c336326021be751f78a8345dfb21a89774dcdfcf86a2f9ceeda701c4703075128a");
        let b = hex("07b62afb7755c2ecb395d2e83b3ba26dcd1ce656da29e20e14e18497571e64309b64e13bf14e9268c7531e6674a8ce5c279fb516e58eef55d524febedba6fe16");
        let c = hex("32b22e6559930133086d2b9ddd3636ca7e5624e110b26cbff2fb43511ba33eb8f0b2ef716585a97d7e30fc2c6ac0cd2bbfe8faeffd61dc0c88d7a2956eb26da3");
        let expected = hex("da79cc8e9262ac13872bc809d0025f6ee7dd379bdf52eea5254d05d49576694b5deb2f458ce2b27fa557c8f53fc0e66a42a813a7158fce87fa454a4c94fdf047");
        assert_eq!(mix(&a, &b, &c), expected);
    }

    #[test]
    fn xor_is_self_inverse() {
        let data = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let mask = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee];
        let once = xor_buffers(&data, &mask);
        assert_eq!(xor_buffers(&once, &mask), data);
    }

    fn hex(s: &str) -> Vec<u8> {
        let mut out = alloc::vec![0u8; s.len() / 2];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }
}
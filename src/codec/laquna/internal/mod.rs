// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Vendored laquna v0.2.0 internals — the substrate's default at-rest
//! content-codec mechanics (rev 3 §3.1).
//!
//! Imported from the laquna v0.2.0 crate (`github.com/skydeval/laquna`,
//! MPL-2.0) modulo the documented vendoring adaptations: the crate-level
//! `#![no_std]` attribute and the `alloc` / `std` / `testing-internals`
//! feature gates are stripped (kryphocron is a `std` crate with `alloc`
//! available unconditionally), the `testing-internals` module is not
//! vendored, and intra-crate `crate::` paths are rebased onto this
//! submodule (`crate::DecodeError` → `super::DecodeError`,
//! `crate::materials` → `super::super::materials`). Function bodies, error
//! types, stream generators, and the inline reference-vector tests are
//! byte-for-byte verbatim, with two kryphocron-side changes: an optional
//! caller-chosen bound on decoded size ([`decode_with_limit`]; [`decode`]
//! keeps the original unbounded behaviour), and the decode path ported from
//! ruzstd 0.7 to 0.9.1 (RUSTSEC-2026-0344). The artifact format is unchanged.
//! The public `ContentCodec` adapter lives in the parent module (`super`).
//!
//! laquna — a deterministic, reversible byte transform for at-rest content
//! opacity. Given a plaintext, an opaque `seed`, and a 32-byte `slug`,
//! [`encode`] produces an artifact whose payload is opaque to casual
//! inspection; given that artifact and the same seed, [`decode`] recovers
//! the plaintext.
//!
//! **laquna is not encryption.** The decoder ships in this repository, the
//! slug travels inline in every artifact, and the seed is typically derived
//! from public metadata. laquna's value is friction against opportunistic,
//! at-scale content extraction — not confidentiality, authentication, or
//! resistance to a motivated adversary.

mod errors;
pub use errors::DecodeError;

mod combine;
mod format;
mod materials;
mod streams;

use alloc::vec::Vec;

use materials::Material;

/// Encode `plaintext` into an opaque artifact.
///
/// `seed` carries per-record entropy and is treated as opaque bytes; it must be unique
/// per record within a slug (the consuming system is responsible for that uniqueness).
/// `slug` is the 32-byte rotation-batch identifier, embedded inline in the output.
///
/// # Panics
///
/// Panics if `seed` is empty. An empty seed cannot satisfy the per-record uniqueness
/// requirement and is treated as a caller-precondition violation.
///
/// # Determinism
///
/// Encoding is deterministic: identical `(plaintext, seed, slug)` inputs produce
/// byte-identical artifacts. Consumers that need to hide plaintext equality must ensure
/// seed uniqueness at the granularity at which equality should be hidden.
///
/// # Examples
///
/// (Illustrative — these are crate-internal vendored functions, not the
/// original `laquna` crate's public API; `ignore`d as a doc-test.)
///
/// ```ignore
/// let slug = [0x5a_u8; 32];
/// let seed = b"did:plc:example||3kabcd2lqr7s2y||per-record-unique";
///
/// let artifact = encode(b"a private post", seed, &slug);
/// assert_eq!(decode(&artifact, seed).unwrap(), b"a private post");
/// ```
pub fn encode(plaintext: &[u8], seed: &[u8], slug: &[u8; 32]) -> Vec<u8> {
    assert!(!seed.is_empty(), "laquna: seed must be non-empty");

    let payload_input = compress(plaintext);
    let material = materials::derive(seed, slug);
    let mask = build_mask(&material, payload_input.len());
    let payload = combine::xor_buffers(&payload_input, &mask);

    format::assemble(payload, slug)
}

/// Decode an artifact back to its plaintext.
///
/// The 32-byte slug is read from the tail of `encoded`; the caller supplies only the
/// `seed` used at encode time. The seed must reproduce the value used when the artifact
/// was encoded, or recovery fails.
///
/// # Errors
///
/// - [`DecodeError::EmptySeed`] if `seed` is empty (checked before any structural
///   inspection of `encoded`).
/// - [`DecodeError::InputTooShort`] if `encoded` is shorter than the minimum length.
/// - [`DecodeError::InvalidVersion`] if the leading version byte is not the one this
///   version of the format accepts.
/// - [`DecodeError::DecompressionFailed`] if the recovered bytes fail to validate —
///   typically a wrong seed, a wrong slug, or corruption.
#[cfg_attr(not(test), allow(dead_code))] // the adapter calls `decode_with_limit`
pub fn decode(encoded: &[u8], seed: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_with_limit(encoded, seed, None)
}

/// [`decode`] with an optional bound on the decoded length.
///
/// With `max_decoded_len: Some(n)`, an artifact whose plaintext would exceed `n`
/// bytes fails as [`DecodeError::DecompressionFailed`] without being fully
/// decompressed: a frame whose header declares a content size or window larger
/// than `n` is refused before any block is decoded, and otherwise decoding stops
/// as soon as the output passes `n`. Peak memory stays within a small multiple
/// of `n` (the output plus the decoder's window, which the header check caps at
/// `n`, plus one zstd block). `None` is unbounded, as [`decode`].
pub fn decode_with_limit(
    encoded: &[u8],
    seed: &[u8],
    max_decoded_len: Option<usize>,
) -> Result<Vec<u8>, DecodeError> {
    if seed.is_empty() {
        return Err(DecodeError::EmptySeed);
    }

    let (payload, slug) = format::disassemble(encoded)?;
    let material = materials::derive(seed, &slug);
    let mask = build_mask(&material, payload.len());
    let payload_input = combine::xor_buffers(&payload, &mask);

    decompress(&payload_input, max_decoded_len)
}

/// Build the mask by producing the three component streams and folding them together.
fn build_mask(material: &Material, length: usize) -> Vec<u8> {
    let mut anchor = streams::anchor::AnchorGenerator::new(material);
    let mut extendable = streams::extendable::ExtendableGenerator::new(material);
    let mut network = streams::network::NetworkGenerator::new(material);

    let stream_a = anchor.produce(length);
    let stream_b = extendable.produce(length);
    let stream_c = network.produce(length);

    combine::mix(&stream_a, &stream_b, &stream_c)
}

/// Compress the plaintext ahead of masking.
///
/// The content-checksum frame flag is enabled so the decode path can catch a class of
/// wrong-seed and corruption cases that would otherwise decompress to silent garbage.
fn compress(plaintext: &[u8]) -> Vec<u8> {
    use zstd::bulk::Compressor;
    use zstd::stream::raw::CParameter;

    let mut compressor = Compressor::new(3).expect("compression level 3 is valid");
    compressor
        .set_parameter(CParameter::ChecksumFlag(true))
        .expect("enabling the content-checksum frame flag is supported");
    compressor
        .compress(plaintext)
        .expect("compression of an in-memory buffer does not fail")
}

/// Reverse [`compress`], surfacing any validation failure as a [`DecodeError`].
///
/// The content checksum carried in the frame is compared manually here: the decoder
/// reads and recomputes it but does not compare them itself, so a mismatch would
/// otherwise pass silently. Any parse, decode, or checksum failure maps to
/// [`DecodeError::DecompressionFailed`].
///
/// With `max_decoded_len: Some(n)` (see [`decode_with_limit`]), exceeding `n`
/// is one more such failure.
fn decompress(
    payload_input: &[u8],
    max_decoded_len: Option<usize>,
) -> Result<Vec<u8>, DecodeError> {
    use ruzstd::io::Read;

    let mut decoder = open_decoder(payload_input, max_decoded_len)?;

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let read = decoder
            .read(&mut buf)
            .map_err(|_| DecodeError::DecompressionFailed)?;
        if read == 0 {
            break;
        }
        if let Some(limit) = max_decoded_len {
            if out.len() + read > limit {
                return Err(DecodeError::DecompressionFailed);
            }
        }
        out.extend_from_slice(&buf[..read]);
    }

    let frame = decoder.into_frame_decoder();
    if let Some(stored) = frame.get_checksum_from_data() {
        match frame.get_calculated_checksum() {
            Some(computed) if computed == stored => {}
            _ => return Err(DecodeError::DecompressionFailed),
        }
    }

    Ok(out)
}

/// zstd's minimum window size (RFC 8878); ruzstd keeps its own copy private.
const MIN_WINDOW_SIZE: u64 = 1024;

type Decoder<'a> = ruzstd::decoding::StreamingDecoder<&'a [u8], ruzstd::decoding::FrameDecoder>;

/// Read the frame header and open a decoder, refusing a frame whose header
/// already shows it cannot fit in `max_decoded_len` bytes.
///
/// ruzstd buffers up to a window of output before it hands bytes back, so the
/// read-loop count in [`decompress`] alone would let a small frame claim that
/// much memory first. With `Some(limit)`, two header checks close this before
/// any block is decoded:
///
/// - a window larger than `limit` (floored at zstd's 1 KiB minimum window) is
///   refused by the decoder itself, before it allocates the window. Frames from
///   [`compress`] are single-segment, so their window equals their content size
///   and passes whenever the content does;
/// - a declared content size larger than `limit` is refused.
///
/// Each block's output is bounded by the decoder (at most the smaller of the
/// window and 128 KiB, per RFC 8878; enforced since ruzstd 0.9.1), so between
/// reads the decoder holds at most a window plus one block.
///
/// With `None`, ruzstd's default window bound applies. Any header error maps to
/// [`DecodeError::DecompressionFailed`].
fn open_decoder(
    payload_input: &[u8],
    max_decoded_len: Option<usize>,
) -> Result<Decoder<'_>, DecodeError> {
    use ruzstd::decoding::StreamingDecoder;

    let Some(limit) = max_decoded_len else {
        return StreamingDecoder::new(payload_input).map_err(|_| DecodeError::DecompressionFailed);
    };
    let limit = limit as u64;
    let decoder = StreamingDecoder::new_with_max_window_size(payload_input, limit.max(MIN_WINDOW_SIZE))
        .map_err(|_| DecodeError::DecompressionFailed)?;
    // `content_size` is 0 when the header declares none; such a frame is
    // bounded by the read-loop count instead.
    if decoder.decoder.content_size() > limit {
        return Err(DecodeError::DecompressionFailed);
    }
    Ok(decoder)
}

/// The header checks of [`open_decoder`] alone, for tests.
#[cfg(test)]
fn check_frame_header_within(payload_input: &[u8], limit: usize) -> Result<(), DecodeError> {
    open_decoder(payload_input, Some(limit)).map(|_| ())
}

#[cfg(test)]
mod decode_limit_tests {
    use super::*;
    use std::time::{Duration, Instant};

    const SEED: &[u8] = b"did:plc:example||tools.example.post||3kabcd2lqr7s2y";
    const SLUG: [u8; 32] = [0x5a; 32];

    /// Mask and frame a raw zstd stream exactly as `encode` does after
    /// compression, so hand-built frames reach `decompress` through `decode`.
    fn artifact_from_zstd(raw: &[u8]) -> Vec<u8> {
        let material = materials::derive(SEED, &SLUG);
        let mask = build_mask(&material, raw.len());
        format::assemble(combine::xor_buffers(raw, &mask), &SLUG)
    }

    /// A zstd frame of `blocks` RLE blocks, each expanding one byte to
    /// `block_len` bytes. No content size, no checksum: a well-formed frame
    /// whose output size is visible only by decoding it.
    fn rle_frame(window_descriptor: u8, block_len: u32, blocks: usize) -> Vec<u8> {
        let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, window_descriptor];
        for i in 0..blocks {
            let last = u32::from(i + 1 == blocks);
            let header = (block_len << 3) | (1 << 1) | last; // type 1 = RLE
            f.extend_from_slice(&header.to_le_bytes()[..3]);
            f.push(0xAB);
        }
        f
    }

    // Window descriptor byte: exponent in bits 7-3, window = 2^(10 + exponent).
    const WINDOW_64_KIB: u8 = 6 << 3;
    const WINDOW_512_KIB: u8 = 9 << 3;
    const WINDOW_64_MIB: u8 = 16 << 3;
    const BLOCK_128_KIB: u32 = 128 * 1024;

    #[test]
    fn encoded_record_at_limit_decodes_and_one_over_fails() {
        let plaintext: Vec<u8> = (0..10_000u32).map(|i| (i * 7919 % 251) as u8).collect();
        let artifact = encode(&plaintext, SEED, &SLUG);

        assert_eq!(decode_with_limit(&artifact, SEED, Some(10_000)).unwrap(), plaintext);
        assert_eq!(decode_with_limit(&artifact, SEED, Some(10_001)).unwrap(), plaintext);
        assert_eq!(decode_with_limit(&artifact, SEED, None).unwrap(), plaintext);
        assert_eq!(
            decode_with_limit(&artifact, SEED, Some(9_999)),
            Err(DecodeError::DecompressionFailed)
        );
    }

    /// Frames without a declared content size are bounded by the read-loop
    /// count, not the header check: exact boundary on that path.
    #[test]
    fn undeclared_size_frame_at_limit_decodes_and_one_over_fails() {
        let total = 16 * 64 * 1024;
        let artifact = artifact_from_zstd(&rle_frame(WINDOW_64_KIB, 64 * 1024, 16));

        let out = decode_with_limit(&artifact, SEED, Some(total)).unwrap();
        assert_eq!(out.len(), total);
        assert!(out.iter().all(|&b| b == 0xAB));
        assert!(matches!(
            decode_with_limit(&artifact, SEED, Some(total - 1)),
            Err(DecodeError::DecompressionFailed)
        ));
    }

    /// 1 GiB of RLE blocks in ~32 KiB of input, window small enough to pass
    /// the header check: the read-loop count must stop it near the limit.
    #[test]
    fn rle_bomb_small_window_fails_fast() {
        // Sanity: the same frame shape is valid and decodes when small.
        let small = artifact_from_zstd(&rle_frame(WINDOW_512_KIB, BLOCK_128_KIB, 4));
        assert_eq!(decode(&small, SEED).unwrap().len(), 4 * 128 * 1024);

        let bomb = artifact_from_zstd(&rle_frame(WINDOW_512_KIB, BLOCK_128_KIB, 8192));
        assert!(bomb.len() < 64 * 1024);
        let start = Instant::now();
        // `matches!`, not `assert_eq!`: a regression would otherwise print 1 GiB.
        assert!(matches!(
            decode_with_limit(&bomb, SEED, Some(1_000_000)),
            Err(DecodeError::DecompressionFailed)
        ));
        assert!(start.elapsed() < Duration::from_secs(2), "took {:?}", start.elapsed());
    }

    /// A frame of an 8-byte raw block, then one compressed block of `sequences`
    /// identical sequences: no literals, a repeat offset into the raw block, and
    /// match-length code `ml_code` with `ml_extra_bits` zero extra bits. All three
    /// sequence tables are RLE mode, so each sequence costs only its extra bits.
    /// Window 64 KiB, no content size, no checksum.
    fn sequence_block_frame(sequences: usize, ml_code: u8, ml_extra_bits: usize) -> Vec<u8> {
        assert!(sequences < 0x7F00);
        assert_eq!(sequences * ml_extra_bits % 8, 0);
        let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, WINDOW_64_KIB];
        // Raw block (type 0), not last.
        f.extend_from_slice(&(8u32 << 3).to_le_bytes()[..3]);
        f.extend_from_slice(b"abcdefgh");

        let mut block = vec![0x00]; // literals section: raw, size 0
        if sequences < 128 {
            block.push(sequences as u8);
        } else {
            block.push((128 + (sequences >> 8)) as u8);
            block.push(sequences as u8);
        }
        block.push(0b01_01_01_00); // literal-length, offset, match-length tables: RLE
        // Literal-length code 0 (none); offset code 0 (value 1: a repeat
        // offset, 4 then 1, both inside the raw block); then the match code.
        block.extend_from_slice(&[0, 0, ml_code]);
        block.resize(block.len() + sequences * ml_extra_bits / 8, 0);
        block.push(0x01); // bitstream end marker, no padding bits

        // Compressed block (type 2), last.
        let header = ((block.len() as u32) << 3) | (2 << 1) | 1;
        f.extend_from_slice(&header.to_le_bytes()[..3]);
        f.extend_from_slice(&block);
        f
    }

    /// The sequence-block frame is well-formed: one 34-byte match (code 31, no
    /// extra bits) decodes to 8 + 34 bytes.
    #[test]
    fn sequence_block_frame_decodes_when_small() {
        let out = decode(&artifact_from_zstd(&sequence_block_frame(1, 31, 0)), SEED).unwrap();
        assert_eq!(out.len(), 8 + 34);
        assert_eq!(&out[..12], b"abcdefghefgh");
    }

    /// RUSTSEC-2026-0344: one compressed block whose sequences expand to about
    /// 65 MB, far past zstd's per-block maximum (the smaller of the window and
    /// 128 KiB). The window is small, so the header checks pass; before ruzstd
    /// 0.9.1 the decoder built the whole block in memory before returning a byte,
    /// past both the window bound and the read-loop count. The decoder must
    /// refuse the block itself, with or without a decoded-size bound.
    #[test]
    fn oversized_block_refused_by_decoder() {
        // Match-length code 52: 65 539 bytes plus 16 extra bits (zero here).
        let bomb = artifact_from_zstd(&sequence_block_frame(1000, 52, 16));
        assert!(bomb.len() < 4096);
        let start = Instant::now();
        // `matches!`, not `assert_eq!`: a regression would otherwise print 65 MB.
        assert!(matches!(decode(&bomb, SEED), Err(DecodeError::DecompressionFailed)));
        assert!(matches!(
            decode_with_limit(&bomb, SEED, Some(1_000_000)),
            Err(DecodeError::DecompressionFailed)
        ));
        assert!(start.elapsed() < Duration::from_secs(2), "took {:?}", start.elapsed());
    }

    /// A 64 MiB window would let ruzstd buffer 64 MiB before yielding a byte;
    /// the header check refuses it before any block is decoded.
    #[test]
    fn rle_bomb_large_window_refused_by_header() {
        let small = artifact_from_zstd(&rle_frame(WINDOW_64_MIB, BLOCK_128_KIB, 2));
        assert_eq!(decode(&small, SEED).unwrap().len(), 2 * 128 * 1024);

        let raw = rle_frame(WINDOW_64_MIB, BLOCK_128_KIB, 8192);
        assert_eq!(
            check_frame_header_within(&raw, 1_000_000),
            Err(DecodeError::DecompressionFailed)
        );
        let bomb = artifact_from_zstd(&raw);
        let start = Instant::now();
        assert!(matches!(
            decode_with_limit(&bomb, SEED, Some(1_000_000)),
            Err(DecodeError::DecompressionFailed)
        ));
        assert!(start.elapsed() < Duration::from_secs(2), "took {:?}", start.elapsed());
    }

    /// The header check, not the read-loop count, refuses a window over the
    /// limit: 256 KiB of content fits a 1 MB limit, but its declared 64 MiB
    /// window does not, so decode fails before ruzstd allocates that window.
    #[test]
    fn window_over_limit_refused_even_when_content_fits() {
        let artifact = artifact_from_zstd(&rle_frame(WINDOW_64_MIB, BLOCK_128_KIB, 2));
        assert_eq!(decode_with_limit(&artifact, SEED, None).unwrap().len(), 256 * 1024);
        assert!(matches!(
            decode_with_limit(&artifact, SEED, Some(1_000_000)),
            Err(DecodeError::DecompressionFailed)
        ));
    }

    /// A declared content size over the limit is refused from the header.
    #[test]
    fn declared_content_size_over_limit_refused_by_header() {
        let plaintext = vec![0u8; 50_000];
        let raw = compress(&plaintext);
        assert_eq!(check_frame_header_within(&raw, 50_000), Ok(()));
        assert_eq!(
            check_frame_header_within(&raw, 49_999),
            Err(DecodeError::DecompressionFailed)
        );
    }
}

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
//! byte-for-byte verbatim, with one kryphocron-side addition: an optional
//! caller-chosen bound on decoded size ([`decode_with_limit`]; [`decode`]
//! keeps the original unbounded behaviour). The public `ContentCodec` adapter
//! lives in the parent module (`super`).
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
    use ruzstd::StreamingDecoder;

    if let Some(limit) = max_decoded_len {
        check_frame_header_within(payload_input, limit)?;
    }

    let mut decoder =
        StreamingDecoder::new(payload_input).map_err(|_| DecodeError::DecompressionFailed)?;

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

/// Refuse a frame whose header already shows it cannot fit in `limit` bytes.
///
/// ruzstd keeps a full window of output buffered before it hands any bytes back,
/// and a frame may declare a window of up to 100 MiB; the read-loop count in
/// [`decompress`] alone would therefore let a small frame occupy that much
/// memory first. Two header checks close this:
///
/// - a declared content size larger than `limit` is refused outright;
/// - a window larger than `limit` (floored at zstd's 1 KiB minimum window) is
///   refused. Frames from [`compress`] are single-segment, so their window
///   equals their content size and passes whenever the content does.
///
/// A header that fails to parse is left for the decoder to reject as before.
fn check_frame_header_within(payload_input: &[u8], limit: usize) -> Result<(), DecodeError> {
    let Ok((frame, _)) = ruzstd::frame::read_frame_header(payload_input) else {
        return Ok(());
    };
    let header = &frame.header;
    let limit = limit as u64;

    let declares_content_size =
        matches!(header.descriptor.frame_content_size_bytes(), Ok(n) if n > 0);
    if declares_content_size && header.frame_content_size() > limit {
        return Err(DecodeError::DecompressionFailed);
    }
    if let Ok(window) = header.window_size() {
        if window > limit.max(ruzstd::frame::MIN_WINDOW_SIZE) {
            return Err(DecodeError::DecompressionFailed);
        }
    }
    Ok(())
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

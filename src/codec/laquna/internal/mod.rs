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
//! byte-for-byte verbatim. The public `ContentCodec` adapter lives in the
//! parent module (`super`).
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
pub fn decode(encoded: &[u8], seed: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if seed.is_empty() {
        return Err(DecodeError::EmptySeed);
    }

    let (payload, slug) = format::disassemble(encoded)?;
    let material = materials::derive(seed, &slug);
    let mask = build_mask(&material, payload.len());
    let payload_input = combine::xor_buffers(&payload, &mask);

    decompress(&payload_input)
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
fn decompress(payload_input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    use ruzstd::io::Read;
    use ruzstd::StreamingDecoder;

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

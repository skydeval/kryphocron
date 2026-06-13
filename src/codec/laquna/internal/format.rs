// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! Artifact byte layout.
//!
//! An artifact is `[version byte][payload][32-byte slug]`. This module owns the
//! version byte, the tail placement of the slug, and the structural pre-checks that
//! guard disassembly. It does not touch the payload contents — that is the mask
//! pipeline's job (see `lib.rs`).

use alloc::vec::Vec;

use super::DecodeError;

/// The leading byte of every artifact this version of the format produces and accepts.
pub(crate) const VERSION: u8 = 0x02;

/// Length of the inline slug, in bytes.
pub(crate) const SLUG_LEN: usize = 32;

/// Smallest structurally-valid artifact: version byte + empty payload + slug.
pub(crate) const MIN_LEN: usize = 1 + SLUG_LEN;

/// Concatenate `[version][payload][slug]` into the finished artifact.
pub(crate) fn assemble(payload: Vec<u8>, slug: &[u8; SLUG_LEN]) -> Vec<u8> {
    let mut artifact = Vec::with_capacity(1 + payload.len() + SLUG_LEN);
    artifact.push(VERSION);
    artifact.extend_from_slice(&payload);
    artifact.extend_from_slice(slug);
    artifact
}

/// Validate the structural pre-checks and split an artifact into `(payload, slug)`.
///
/// The length check precedes the version check, so a buffer too short to even hold a
/// version byte and a slug is reported as too short rather than as a bad version.
pub(crate) fn disassemble(encoded: &[u8]) -> Result<(Vec<u8>, [u8; SLUG_LEN]), DecodeError> {
    if encoded.len() < MIN_LEN {
        return Err(DecodeError::InputTooShort);
    }
    if encoded[0] != VERSION {
        return Err(DecodeError::InvalidVersion(encoded[0]));
    }

    let split = encoded.len() - SLUG_LEN;
    let payload = encoded[1..split].to_vec();
    let mut slug = [0u8; SLUG_LEN];
    slug.copy_from_slice(&encoded[split..]);
    Ok((payload, slug))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_short_is_reported_before_version() {
        // 32 bytes is one below the floor; even with a valid version byte it is short.
        let mut buf = [0u8; 32];
        buf[0] = VERSION;
        assert_eq!(disassemble(&buf), Err(DecodeError::InputTooShort));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut buf = [0u8; MIN_LEN];
        buf[0] = 0x01;
        assert_eq!(disassemble(&buf), Err(DecodeError::InvalidVersion(0x01)));
    }

    #[test]
    fn splits_payload_and_tail_slug() {
        let slug = [0xa5u8; SLUG_LEN];
        let payload = alloc::vec![0xde, 0xad, 0xbe, 0xef];
        let artifact = {
            let mut a = alloc::vec![VERSION];
            a.extend_from_slice(&payload);
            a.extend_from_slice(&slug);
            a
        };
        let (got_payload, got_slug) = disassemble(&artifact).unwrap();
        assert_eq!(got_payload, payload);
        assert_eq!(got_slug, slug);
    }

    #[test]
    fn minimum_length_artifact_has_empty_payload() {
        let slug = [0x11u8; SLUG_LEN];
        let mut artifact = alloc::vec![VERSION];
        artifact.extend_from_slice(&slug);
        let (payload, got_slug) = disassemble(&artifact).unwrap();
        assert!(payload.is_empty());
        assert_eq!(got_slug, slug);
    }
}
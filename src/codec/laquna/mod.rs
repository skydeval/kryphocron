// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Laquna — the substrate's default at-rest content codec (rev 3 §3).
//!
//! kryphocron deployments encode private-tier record content at rest via
//! this codec by default (the constitutional encoding-at-default floor, rev
//! 3 §1 / §2.1). Laquna is a deterministic, reversible **friction** transform
//! — opacity against opportunistic, at-scale content extraction. It is **not
//! encryption**: it provides no confidentiality, authentication, or
//! resistance to a motivated adversary (the decoder ships in this crate and
//! the per-record seed is derived from public metadata). Operators needing
//! stronger guarantees substitute a strengthening codec via
//! `DefaultAtRestHooksBuilder::with_codec` (rev 3 §5.1 / §5.5).
//!
//! The encoding *mechanics* are the vendored laquna v0.2.0 source in
//! `internal`; this module is the [`ContentCodec`] adapter that bridges
//! laquna's stateless sync free functions to the substrate's stateful async
//! trait, deriving the per-record seed from the record-identity tuple and
//! recovering the rotation slug from the rotation oracle's generation mark.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use crate::encryption::{
    CodecError, CodecId, ContentCodec, DecodeContext, EncodeContext, EncodedRecord,
    RotationGenerationMark,
};
use crate::proto::{Did, Nsid, RecordKey};

mod internal;
pub use internal::DecodeError;

/// The default kryphocron at-rest content codec.
///
/// Construction:
/// - [`Codec::default`] — recommended; uses the `{originator}||{nsid}||{rkey}`
///   seed-derivation recipe (§3.3).
/// - [`Codec::new`] — custom seed-derivation policy for operators with
///   non-default deployment constraints.
///
/// Stateful only in the configured seed-derivation policy; no per-encode
/// mutable state.
#[derive(Clone)]
pub struct Codec {
    seed_policy: SeedPolicy,
}

/// Seed-derivation policy. The substrate computes the per-record seed by
/// applying this policy to the [`EncodeContext`] / [`DecodeContext`]. The
/// default policy concatenates the originator DID, NSID, and rkey separated
/// by `||`.
#[derive(Clone)]
pub enum SeedPolicy {
    /// `{originator}||{nsid}||{rkey}` — default; per-record uniqueness via the
    /// substrate's record-identity tuple (the three identity components rev 6's
    /// [`EncodeContext`] / [`DecodeContext`] already carry as separate fields).
    DidNsidRkey,

    /// Operator-supplied closure for custom recipes. The closure receives the
    /// full [`EncodeContext`] reference and returns the seed bytes. The
    /// substrate enforces the "non-empty seed" precondition before calling
    /// laquna (via `debug_assert!` — see §3.3).
    ///
    /// The closure operates on `&EncodeContext` directly rather than a derived
    /// projection (rev 3 deliberately introduces no new public `RecordIdentity`
    /// type — §10). On the decode side the adapter synthesizes an equivalent
    /// `EncodeContext` from the [`DecodeContext`]'s matching identity fields
    /// (with `current_generation_hint: None`, since decode reads the slug from
    /// the stored artifact, not the oracle).
    //
    // The inline closure type is the rev 3 §3.2 surface verbatim; a `type`
    // alias would be new public API (§10 admits only
    // `RotationOracleConstructionError`), so the complexity lint is allowed
    // locally rather than factored out into a public alias.
    #[allow(clippy::type_complexity)]
    Custom(Arc<dyn Fn(&EncodeContext) -> Vec<u8> + Send + Sync>),
}

impl Default for Codec {
    fn default() -> Self {
        Self {
            seed_policy: SeedPolicy::DidNsidRkey,
        }
    }
}

impl Codec {
    /// Construct a codec with a custom [`SeedPolicy`].
    #[must_use]
    pub fn new(seed_policy: SeedPolicy) -> Self {
        Self { seed_policy }
    }
}

// `SeedPolicy::Custom` holds a closure (not `Debug`); hand-write `Debug` so
// `Codec` stays diagnostic-printable without exposing the closure.
impl std::fmt::Debug for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Codec")
            .field("seed_policy", &self.seed_policy)
            .finish()
    }
}

impl std::fmt::Debug for SeedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedPolicy::DidNsidRkey => f.write_str("DidNsidRkey"),
            SeedPolicy::Custom(_) => f.write_str("Custom(<closure>)"),
        }
    }
}

/// The default seed recipe: ASCII `{originator}||{nsid}||{rkey}` (§3.3).
///
/// Takes the three identity components directly so the same recipe serves both
/// the encode (`EncodeContext`) and decode (`DecodeContext`) sides. Output is
/// non-empty by ATProto identity rules (the three components are non-empty);
/// the caller `debug_assert!`s this defensively.
fn derive_seed_did_nsid_rkey(originator: &Did, nsid: &Nsid, rkey: &RecordKey) -> Vec<u8> {
    format!("{}||{}||{}", originator.as_str(), nsid.as_str(), rkey.as_str()).into_bytes()
}

/// Project a [`DecodeContext`] into an equivalent [`EncodeContext`] for
/// `SeedPolicy::Custom` decode-side seed derivation (rev 3 §3.4 Option 1).
///
/// Copies the four identity fields plus `trace_id` / `operator_context`;
/// `current_generation_hint` is `None` because decode recovers the slug from
/// the stored artifact's tail, not from the rotation oracle.
fn decode_ctx_as_encode_ctx(ctx: &DecodeContext) -> EncodeContext {
    EncodeContext {
        nsid: ctx.nsid.clone(),
        rkey: ctx.rkey.clone(),
        originator: ctx.originator.clone(),
        audience_list: ctx.audience_list.clone(),
        current_generation_hint: None,
        trace_id: ctx.trace_id,
        operator_context: ctx.operator_context.clone(),
    }
}

/// Parse the 32-byte rotation slug from a [`RotationGenerationMark`].
///
/// Internal to the laquna adapter — adds no public method on
/// `RotationGenerationMark`. Parses the mark format committed by the default
/// rotation oracle (§4.7): `"laquna/{:020}/{hex64}"`. Returns `None` on any
/// malformed input; the caller treats `None` as a substrate-invariant
/// violation (`expect`), since the default oracle always produces this shape.
fn parse_slug_from_mark(mark: &RotationGenerationMark) -> Option<[u8; 32]> {
    let s: &str = mark.as_str();
    // Expect ["laquna", "<unix_secs>", "<hex_slug>"].
    let mut parts = s.splitn(3, '/');
    let prefix = parts.next()?;
    let _unix_secs = parts.next()?; // present for lex ordering; only the slug is needed here
    let hex_slug = parts.next()?;
    if prefix != "laquna" || hex_slug.len() != 64 {
        return None;
    }
    let mut slug = [0u8; 32];
    hex::decode_to_slice(hex_slug, &mut slug).ok()?;
    Some(slug)
}

#[async_trait]
impl ContentCodec for Codec {
    fn codec_id(&self) -> CodecId {
        // Stable for the lifetime of records encoded under it (§3.6). Future
        // byte-compatible laquna-internals bumps keep `"laquna/0.2"`.
        CodecId::new("laquna/0.2").expect("\"laquna/0.2\" is a valid codec id")
    }

    fn requires_rotation(&self) -> bool {
        // The slug is laquna's rotation-batch identifier; friction degrades
        // when one slug stamps many records (§3.5). The install seam
        // fail-closes if no rotation oracle is installed.
        true
    }

    async fn encode(
        &self,
        plaintext: &[u8],
        context: &EncodeContext,
        _deadline: Instant,
    ) -> Result<Vec<u8>, CodecError> {
        let seed = match &self.seed_policy {
            SeedPolicy::DidNsidRkey => {
                derive_seed_did_nsid_rkey(&context.originator, &context.nsid, &context.rkey)
            }
            SeedPolicy::Custom(f) => f(context),
        };
        // Substrate invariant: non-empty under `DidNsidRkey` (ATProto rules)
        // and under `Custom` (operator-supplied contract). An empty seed is an
        // invariant violation, not a runtime condition — no new `CodecError`
        // variant (§3.4 error-variant policy).
        debug_assert!(
            !seed.is_empty(),
            "substrate invariant: seed must be non-empty"
        );

        // The rotation generation is sourced by the substrate from the
        // installed oracle and already freshness-checked. Under
        // `DefaultAtRestHooks` the install seam guarantees a rotation oracle is
        // present (laquna `requires_rotation() -> true` + the rev 6.1 §11 item
        // 8 install check), so the hint is `Some` here. A `None` means an
        // operator constructed hooks bypassing the install seam — unsupported.
        let mark = context.current_generation_hint.as_ref().expect(
            "substrate invariant: rotation oracle must be installed \
             (install-seam check enforces this for codecs declaring \
             requires_rotation -> true)",
        );
        let slug = parse_slug_from_mark(mark).expect(
            "substrate invariant: rotation mark must match the default \
             oracle's format (§4.7)",
        );

        // Laquna's encode is sync + CPU-bound (zstd). At typical record sizes
        // (a few KB) the blocking compression is microseconds; ~1MB lexicon
        // upper-bound records compress in low single-digit ms — within
        // async-runtime expectations, so no spawn_blocking. The deadline is
        // accepted but unused.
        Ok(internal::encode(plaintext, &seed, &slug))
    }

    async fn decode(
        &self,
        encoded: &EncodedRecord,
        context: &DecodeContext,
        _deadline: Instant,
    ) -> Result<Vec<u8>, CodecError> {
        // Decode-side seed derivation projects the same identity fields. The
        // slug is read from the stored artifact's tail by laquna's decoder, so
        // no rotation mark is needed here.
        let seed = match &self.seed_policy {
            SeedPolicy::DidNsidRkey => {
                derive_seed_did_nsid_rkey(&context.originator, &context.nsid, &context.rkey)
            }
            SeedPolicy::Custom(f) => f(&decode_ctx_as_encode_ctx(context)),
        };
        debug_assert!(
            !seed.is_empty(),
            "substrate invariant: seed must be non-empty"
        );

        // Decode failure maps to the existing rev-6 `CodecError::Malformed`
        // (wrong seed, wrong slug, or corruption). The laquna-side `DecodeError`
        // carries no detail by design; the adapter introduces no
        // `DecodeFailed(String)` variant (§3.4).
        internal::decode(&encoded.content, &seed)
            .map_err(|_e| CodecError::Malformed {
                codec: self.codec_id(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TraceId;

    fn mark_with_slug(slug: [u8; 32]) -> RotationGenerationMark {
        // The default oracle's §4.7 format: "laquna/{:020}/{hex64}".
        RotationGenerationMark::new(format!(
            "laquna/{:020}/{}",
            1_700_000_000u64,
            hex::encode(slug)
        ))
        .expect("mark fits the BoundedString bound")
    }

    fn enc_ctx(rkey: &str, mark: RotationGenerationMark) -> EncodeContext {
        EncodeContext {
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            rkey: RecordKey::new(rkey).unwrap(),
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            audience_list: None,
            current_generation_hint: Some(mark),
            trace_id: TraceId::from_bytes([0xAB; 16]),
            operator_context: Default::default(),
        }
    }

    fn dec_ctx(rkey: &str) -> DecodeContext {
        DecodeContext {
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            rkey: RecordKey::new(rkey).unwrap(),
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            audience_list: None,
            trace_id: TraceId::from_bytes([0xAB; 16]),
            operator_context: Default::default(),
        }
    }

    /// The default codec round-trips: encode then decode recovers the
    /// plaintext, and the encoded bytes are not the plaintext.
    #[tokio::test]
    async fn default_codec_round_trips() {
        let codec = Codec::default();
        let mark = mark_with_slug([0x5a; 32]);
        let plaintext = b"a private post body";
        let deadline = Instant::now();

        let content = codec
            .encode(plaintext, &enc_ctx("3kabcdefghij2", mark.clone()), deadline)
            .await
            .expect("encode succeeds");
        assert_ne!(content.as_slice(), plaintext.as_slice(), "encoded bytes are not plaintext");

        let record = EncodedRecord {
            codec: codec.codec_id(),
            content,
            generation: Some(mark),
        };
        let recovered = codec
            .decode(&record, &dec_ctx("3kabcdefghij2"), deadline)
            .await
            .expect("decode succeeds");
        assert_eq!(recovered, plaintext);
    }

    /// Decoding with a different record-identity seed (different rkey →
    /// different derived seed) fails closed as `Malformed`.
    #[tokio::test]
    async fn decode_with_wrong_identity_seed_is_malformed() {
        let codec = Codec::default();
        let mark = mark_with_slug([0x5a; 32]);
        let deadline = Instant::now();
        let content = codec
            .encode(b"secret", &enc_ctx("3kabcdefghij2", mark.clone()), deadline)
            .await
            .unwrap();
        let record = EncodedRecord {
            codec: codec.codec_id(),
            content,
            generation: Some(mark),
        };
        let err = codec
            .decode(&record, &dec_ctx("3kabcdefghij3"), deadline)
            .await
            .unwrap_err();
        assert!(matches!(err, CodecError::Malformed { .. }));
    }

    #[test]
    fn codec_id_is_laquna_0_2() {
        assert_eq!(Codec::default().codec_id().as_str(), "laquna/0.2");
    }

    #[test]
    fn requires_rotation_is_true() {
        assert!(Codec::default().requires_rotation());
    }
}

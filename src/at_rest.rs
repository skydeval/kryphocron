// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §8.3 at-rest content encode / decode seams.
//!
//! These two functions are the substrate-side plumbing that drives an
//! installed [`ContentCodec`] (§8.3) for private-tier record content:
//!
//! - [`encode_record_content`] resolves the rotation generation (freshness-
//!   checked via [`resolve_rotation_generation`]), invokes
//!   [`ContentCodec::encode`], wraps the returned bytes into an
//!   [`EncodedRecord`] **stamped by the substrate** (the codec has no
//!   authority over the `codec` / `generation` metadata), and emits the
//!   success / failure audit event.
//! - [`decode_record_content`] verifies the stored codec against the
//!   installed [`ContentCodec::codec_id`], invokes [`ContentCodec::decode`],
//!   and emits a failure audit event on any failure.
//!
//! **The substrate is the audit emitter, not the codec** (rev6 §6.2/§6.3):
//! whether a failure arose in rotation resolution, codec-id verification, or
//! inside the codec, the event is emitted here. Audit emission is
//! **fire-and-forget** at this seam (`let _ = sink.record(..)`), matching the
//! non-bind precedent (`crate::ingress`'s `DerivedContext` emit): the §4.9
//! audit-unavailable-is-fail-closed discipline is specific to the §4.3
//! capability bind path, which content encode/decode is not.
//!
//! With no codec installed, [`encode_record_content`] returns `Ok(None)` — the
//! caller stores the plaintext in the lexicon `text` field (the [`NoAtRestHooks`]
//! baseline). [`NoAtRestHooks`]: crate::encryption::NoAtRestHooks

use std::time::{Instant, SystemTime};

use smallvec::SmallVec;

use crate::audit::{UserAuditEvent, UserAuditSink};
use crate::encryption::{
    resolve_rotation_generation, AtRestHooks, CodecError, CodecErrorClass, CodecId, DecodeContext,
    EncodeContext, EncodedRecord, RotationContext,
};
use crate::identity::TraceId;
use crate::proto::{AtUri, Did, Nsid, RecordKey};
use crate::read_pipeline::ReadAuthorization;
use crate::target::TargetRepresentation;

/// Identity / at-URI / audit context for an at-rest content seam call,
/// supplied by the host alongside the payload.
///
/// `#[non_exhaustive]`; construct via [`RecordContentContext::new`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RecordContentContext {
    /// NSID of the record (the at-URI `collection`).
    pub nsid: Nsid,
    /// The at-URI `rkey` component of the record.
    pub rkey: RecordKey,
    /// DID of the record's originator (the at-URI authority).
    pub originator: Did,
    /// Audience-list reference, where applicable.
    pub audience_list: Option<AtUri>,
    /// Requesting principal — the writer on encode, the reader on decode.
    pub requester: Did,
    /// Subject representation (§4.4) recorded on the emitted audit event.
    pub subject_repr: TargetRepresentation,
    /// Trace id correlating to the originating request.
    pub trace_id: TraceId,
    /// Operator-extensible context; the substrate does not interpret these.
    pub operator_context: SmallVec<[(String, Vec<u8>); 2]>,
}

impl RecordContentContext {
    /// Construct a [`RecordContentContext`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nsid: Nsid,
        rkey: RecordKey,
        originator: Did,
        audience_list: Option<AtUri>,
        requester: Did,
        subject_repr: TargetRepresentation,
        trace_id: TraceId,
        operator_context: SmallVec<[(String, Vec<u8>); 2]>,
    ) -> Self {
        RecordContentContext {
            nsid,
            rkey,
            originator,
            audience_list,
            requester,
            subject_repr,
            trace_id,
            operator_context,
        }
    }
}

/// Encode private-tier record content at rest through the installed
/// [`ContentCodec`], stamping the resulting [`EncodedRecord`] from substrate
/// state and emitting the §6.2 audit event.
///
/// Returns `Ok(None)` when no codec is installed — the plaintext path; the
/// caller stores the plaintext in the record's `text` field. Returns
/// `Ok(Some(record))` with the substrate-stamped [`EncodedRecord`] on success.
///
/// `now` is the current wall-clock instant; it is used both for the rotation
/// oracle freshness check and as the emitted event's wallclock.
///
/// # Errors
///
/// [`CodecError`] when the rotation oracle is stale
/// ([`CodecError::RotationStateUnavailable`]) or the codec fails. A
/// [`UserAuditEvent::ContentEncodeFailed`] is emitted before the error returns.
///
/// [`ContentCodec`]: crate::encryption::ContentCodec
pub async fn encode_record_content(
    hooks: &dyn AtRestHooks,
    user_sink: &dyn UserAuditSink,
    plaintext: &[u8],
    ctx: &RecordContentContext,
    deadline: Instant,
    now: SystemTime,
) -> Result<Option<EncodedRecord>, CodecError> {
    let Some(codec) = hooks.content_codec() else {
        // No codec installed: plaintext path. Caller stores plaintext in `text`.
        return Ok(None);
    };
    let codec_id = codec.codec_id();

    // Resolve the rotation generation — freshness-checked in substrate code.
    let rotation_ctx = RotationContext {
        originator: ctx.originator.clone(),
        nsid: ctx.nsid.clone(),
        audience_list: ctx.audience_list.clone(),
    };
    let oracle = hooks.rotation_oracle();
    let generation =
        match resolve_rotation_generation(oracle.as_deref(), &codec_id, &rotation_ctx, now) {
            Ok(g) => g,
            Err(e) => {
                emit_encode_failed(user_sink, ctx, codec_id, e.class(), now);
                return Err(e);
            }
        };

    let encode_ctx = EncodeContext {
        nsid: ctx.nsid.clone(),
        rkey: ctx.rkey.clone(),
        originator: ctx.originator.clone(),
        audience_list: ctx.audience_list.clone(),
        current_generation_hint: generation.clone(),
        trace_id: ctx.trace_id,
        operator_context: ctx.operator_context.clone(),
    };

    let content = match codec.encode(plaintext, &encode_ctx, deadline).await {
        Ok(c) => c,
        Err(e) => {
            emit_encode_failed(user_sink, ctx, codec_id, e.class(), now);
            return Err(e);
        }
    };

    // The substrate stamps the metadata — the codec returns bytes only.
    let record = EncodedRecord {
        codec: codec_id.clone(),
        content,
        generation: generation.clone(),
    };

    let _ = user_sink.record(UserAuditEvent::ContentEncoded {
        trace_id: ctx.trace_id,
        requester: ctx.requester.clone(),
        subject_repr: ctx.subject_repr.clone(),
        codec: codec_id,
        generation,
        at: now,
    });

    Ok(Some(record))
}

/// Decode private-tier record content at rest through the installed
/// [`ContentCodec`], after verifying the stored codec matches, and emitting a
/// §6.3 audit event on any failure.
///
/// **Requires the [`ReadAuthorization`] witness** — by type, this cannot be
/// called before the §4.5 audience-oracle check authorized the read, so the
/// emitted failure event opens no enumeration channel. The reader recorded is
/// `authz.reader()`. `now` is the emitted event's wallclock.
///
/// # Errors
///
/// - [`CodecError::NoCodecInstalled`] when this deployment has no codec but the
///   record carries codec-encoded content (cross-peer codec skew, or a
///   pre-codec historical record).
/// - [`CodecError::UnknownOrWrongCodec`] when the record's stored codec does
///   not match the installed codec.
/// - The codec's own [`CodecError`] on a decode failure.
///
/// A [`UserAuditEvent::ContentDecodeFailed`] is emitted before any error
/// returns.
///
/// [`ContentCodec`]: crate::encryption::ContentCodec
pub async fn decode_record_content(
    authz: &ReadAuthorization,
    hooks: &dyn AtRestHooks,
    user_sink: &dyn UserAuditSink,
    encoded: &EncodedRecord,
    ctx: &RecordContentContext,
    deadline: Instant,
    now: SystemTime,
) -> Result<Vec<u8>, CodecError> {
    let Some(codec) = hooks.content_codec() else {
        // No codec installed, but the record carries codec-encoded content.
        let err = CodecError::NoCodecInstalled {
            stored: encoded.codec.clone(),
        };
        emit_decode_failed(
            user_sink,
            ctx,
            authz.reader(),
            None,
            Some(encoded.codec.clone()),
            err.class(),
            now,
        );
        return Err(err);
    };
    let installed = codec.codec_id();

    if encoded.codec != installed {
        let err = CodecError::UnknownOrWrongCodec {
            stored: encoded.codec.clone(),
            installed: installed.clone(),
        };
        emit_decode_failed(
            user_sink,
            ctx,
            authz.reader(),
            Some(installed),
            Some(encoded.codec.clone()),
            err.class(),
            now,
        );
        return Err(err);
    }

    let decode_ctx = DecodeContext {
        nsid: ctx.nsid.clone(),
        rkey: ctx.rkey.clone(),
        originator: ctx.originator.clone(),
        audience_list: ctx.audience_list.clone(),
        trace_id: ctx.trace_id,
        operator_context: ctx.operator_context.clone(),
    };

    match codec.decode(encoded, &decode_ctx, deadline).await {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => {
            emit_decode_failed(user_sink, ctx, authz.reader(), Some(installed), None, e.class(), now);
            Err(e)
        }
    }
}

fn emit_encode_failed(
    user_sink: &dyn UserAuditSink,
    ctx: &RecordContentContext,
    codec: CodecId,
    error_class: CodecErrorClass,
    at: SystemTime,
) {
    let _ = user_sink.record(UserAuditEvent::ContentEncodeFailed {
        trace_id: ctx.trace_id,
        requester: ctx.requester.clone(),
        subject_repr: ctx.subject_repr.clone(),
        codec,
        error_class,
        at,
    });
}

fn emit_decode_failed(
    user_sink: &dyn UserAuditSink,
    ctx: &RecordContentContext,
    reader: &Did,
    codec: Option<CodecId>,
    stored_codec: Option<CodecId>,
    error_class: CodecErrorClass,
    at: SystemTime,
) {
    let _ = user_sink.record(UserAuditEvent::ContentDecodeFailed {
        trace_id: ctx.trace_id,
        requester: reader.clone(),
        subject_repr: ctx.subject_repr.clone(),
        codec,
        stored_codec,
        error_class,
        at,
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::audit::AuditError;
    use crate::encryption::{
        AuditEncryptionResolver, ContentCodec, RotationGenerationMark, RotationOracle,
    };
    use crate::{StructuralRepresentation, TargetRepresentation};

    // ---- stubs ----

    struct StubCodec {
        id: CodecId,
        encode: Result<Vec<u8>, CodecError>,
        decode: Result<Vec<u8>, CodecError>,
    }

    #[async_trait]
    impl ContentCodec for StubCodec {
        fn codec_id(&self) -> CodecId {
            self.id.clone()
        }
        async fn encode(
            &self,
            _plaintext: &[u8],
            _context: &EncodeContext,
            _deadline: Instant,
        ) -> Result<Vec<u8>, CodecError> {
            self.encode.clone()
        }
        async fn decode(
            &self,
            _encoded: &EncodedRecord,
            _context: &DecodeContext,
            _deadline: Instant,
        ) -> Result<Vec<u8>, CodecError> {
            self.decode.clone()
        }
    }

    struct StubOracle {
        generation: Option<RotationGenerationMark>,
        synced: SystemTime,
        bound: Duration,
    }

    impl RotationOracle for StubOracle {
        fn current_generation(&self, _ctx: &RotationContext) -> Option<RotationGenerationMark> {
            self.generation.clone()
        }
        fn last_synced_at(&self) -> SystemTime {
            self.synced
        }
        fn data_freshness_bound(&self) -> Duration {
            self.bound
        }
    }

    struct StubHooks {
        codec: Option<Arc<dyn ContentCodec>>,
        oracle: Option<Arc<dyn RotationOracle>>,
    }

    impl AtRestHooks for StubHooks {
        fn audit(&self) -> Option<Arc<dyn AuditEncryptionResolver>> {
            None
        }
        fn content_codec(&self) -> Option<Arc<dyn ContentCodec>> {
            self.codec.clone()
        }
        fn rotation_oracle(&self) -> Option<Arc<dyn RotationOracle>> {
            self.oracle.clone()
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<UserAuditEvent>>,
    }

    impl UserAuditSink for CapturingSink {
        fn record(&self, event: UserAuditEvent) -> Result<(), AuditError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    // ---- fixtures ----

    fn codec_id() -> CodecId {
        CodecId::new("laquna/0.2").unwrap()
    }

    fn other_codec_id() -> CodecId {
        CodecId::new("other/1.0").unwrap()
    }

    fn ctx() -> RecordContentContext {
        let did = Did::new("did:plc:exampleexampleexample").unwrap();
        RecordContentContext::new(
            Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            RecordKey::new("3kabcdefghij2").unwrap(),
            did.clone(),
            None,
            did.clone(),
            TargetRepresentation::structural_only(StructuralRepresentation::Resource {
                did,
                nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            }),
            TraceId::from_bytes([7; 16]),
            SmallVec::new(),
        )
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn authz() -> ReadAuthorization {
        ReadAuthorization::new_for_test(Did::new("did:plc:exampleexampleexample").unwrap())
    }

    fn fresh_oracle(mark: &str) -> Arc<dyn RotationOracle> {
        Arc::new(StubOracle {
            generation: Some(RotationGenerationMark::new(mark).unwrap()),
            synced: SystemTime::now(),
            bound: Duration::from_secs(3600),
        })
    }

    fn hooks_with(
        encode: Result<Vec<u8>, CodecError>,
        decode: Result<Vec<u8>, CodecError>,
        oracle: Option<Arc<dyn RotationOracle>>,
    ) -> StubHooks {
        StubHooks {
            codec: Some(Arc::new(StubCodec {
                id: codec_id(),
                encode,
                decode,
            })),
            oracle,
        }
    }

    // ---- encode ----

    #[tokio::test]
    async fn encode_success_stamps_metadata_and_emits() {
        let hooks = hooks_with(Ok(b"CIPHER".to_vec()), Ok(vec![]), Some(fresh_oracle("000042")));
        let sink = CapturingSink::default();
        let now = SystemTime::now();
        let rec = encode_record_content(&hooks, &sink, b"hi", &ctx(), deadline(), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.codec, codec_id());
        assert_eq!(rec.content, b"CIPHER");
        assert_eq!(rec.generation.as_ref().unwrap().as_str(), "000042");
        let events = sink.events.lock().unwrap();
        assert!(matches!(
            events.as_slice(),
            [UserAuditEvent::ContentEncoded { .. }]
        ));
    }

    #[tokio::test]
    async fn encode_no_codec_is_plaintext_path() {
        let hooks = StubHooks { codec: None, oracle: None };
        let sink = CapturingSink::default();
        let out = encode_record_content(&hooks, &sink, b"hi", &ctx(), deadline(), SystemTime::now())
            .await
            .unwrap();
        assert!(out.is_none());
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn encode_stale_rotation_fails_and_emits() {
        let stale = Arc::new(StubOracle {
            generation: Some(RotationGenerationMark::new("000042").unwrap()),
            synced: SystemTime::now() - Duration::from_secs(7200),
            bound: Duration::from_secs(3600),
        });
        let hooks = hooks_with(Ok(b"x".to_vec()), Ok(vec![]), Some(stale));
        let sink = CapturingSink::default();
        let err = encode_record_content(&hooks, &sink, b"hi", &ctx(), deadline(), SystemTime::now())
            .await
            .unwrap_err();
        assert_eq!(err.class(), CodecErrorClass::RotationStateUnavailable);
        let events = sink.events.lock().unwrap();
        assert!(matches!(
            events.as_slice(),
            [UserAuditEvent::ContentEncodeFailed {
                error_class: CodecErrorClass::RotationStateUnavailable,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn encode_codec_error_fails_and_emits() {
        let hooks = hooks_with(
            Err(CodecError::BackendUnavailable {
                detail: "down".into(),
            }),
            Ok(vec![]),
            Some(fresh_oracle("000042")),
        );
        let sink = CapturingSink::default();
        let err = encode_record_content(&hooks, &sink, b"hi", &ctx(), deadline(), SystemTime::now())
            .await
            .unwrap_err();
        assert_eq!(err.class(), CodecErrorClass::BackendUnavailable);
        assert!(matches!(
            sink.events.lock().unwrap().as_slice(),
            [UserAuditEvent::ContentEncodeFailed { .. }]
        ));
    }

    // ---- decode ----

    fn encoded_under(codec: CodecId) -> EncodedRecord {
        EncodedRecord {
            codec,
            content: b"CIPHER".to_vec(),
            generation: None,
        }
    }

    #[tokio::test]
    async fn decode_success() {
        let hooks = hooks_with(Ok(vec![]), Ok(b"PLAIN".to_vec()), None);
        let sink = CapturingSink::default();
        let out = decode_record_content(
            &authz(),
            &hooks,
            &sink,
            &encoded_under(codec_id()),
            &ctx(),
            deadline(),
            SystemTime::now(),
        )
        .await
        .unwrap();
        assert_eq!(out, b"PLAIN");
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn decode_codec_mismatch_fails_and_emits() {
        let hooks = hooks_with(Ok(vec![]), Ok(b"PLAIN".to_vec()), None);
        let sink = CapturingSink::default();
        let err = decode_record_content(
            &authz(),
            &hooks,
            &sink,
            &encoded_under(other_codec_id()),
            &ctx(),
            deadline(),
            SystemTime::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CodecError::UnknownOrWrongCodec { .. }));
        let events = sink.events.lock().unwrap();
        assert!(matches!(
            events.as_slice(),
            [UserAuditEvent::ContentDecodeFailed {
                codec: Some(_),
                stored_codec: Some(_),
                error_class: CodecErrorClass::UnknownOrWrongCodec,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn decode_codec_error_fails_and_emits_with_no_stored_codec() {
        let hooks = hooks_with(Ok(vec![]), Err(CodecError::Malformed { codec: codec_id() }), None);
        let sink = CapturingSink::default();
        let err = decode_record_content(
            &authz(),
            &hooks,
            &sink,
            &encoded_under(codec_id()),
            &ctx(),
            deadline(),
            SystemTime::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CodecError::Malformed { .. }));
        assert!(matches!(
            sink.events.lock().unwrap().as_slice(),
            [UserAuditEvent::ContentDecodeFailed {
                stored_codec: None,
                error_class: CodecErrorClass::Malformed,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn decode_no_codec_installed_is_no_codec_installed_error() {
        let hooks = StubHooks { codec: None, oracle: None };
        let sink = CapturingSink::default();
        let err = decode_record_content(
            &authz(),
            &hooks,
            &sink,
            &encoded_under(codec_id()),
            &ctx(),
            deadline(),
            SystemTime::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CodecError::NoCodecInstalled { .. }));
        let events = sink.events.lock().unwrap();
        assert!(matches!(
            events.as_slice(),
            [UserAuditEvent::ContentDecodeFailed {
                codec: None,
                stored_codec: Some(_),
                error_class: CodecErrorClass::NoCodecInstalled,
                ..
            }]
        ));
    }
}

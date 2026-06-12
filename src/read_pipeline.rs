// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §5.4 / rev6 §4.2 private-record structural validation, plus the read-side
//! post-authorization witness.
//!
//! ## The post-auth witness (the structural lock)
//!
//! [`ReadAuthorization`] is an unforgeable witness that the §4.3 / §4.5
//! audience-oracle check authorized a read. It carries a
//! `PhantomData<crate::sealed::Token>`, so **nothing outside this crate can
//! construct one** — a function that takes `&ReadAuthorization` is therefore
//! *compile-time* guaranteed to run only after a successful read
//! authorization. This is the read-side application of the same sealed-token
//! discipline the §4.3 proof types carry. Read-path
//! [`validate_record_for_read`] and [`crate::at_rest::decode_record_content`]
//! both require it, so "structural validation / decode happen after the
//! audience check" is a property of the type system, not a convention a
//! refactor could silently break.
//!
//! The bind-side [`crate::authority::PipelineStage`] uses the token discipline
//! as *audit/denial labels*; the read side uses it as a *structural lock*. Same
//! tool, applied at the strength each path needs. [`ReadPipelineStage`] is the
//! read-side label enum, for reporting symmetry.
//!
//! ## `validate_record`
//!
//! [`validate_record`] is the pure structural rule set over a private-tier
//! record's field combination — the `text` / `encodedContent` XOR, the
//! orphan-metadata rules, and the `policy.audience` `mode == "list"` members
//! rule. Hosts call [`validate_record_for_write`] on the write path (no
//! witness — a write has no upstream authorization stage to defer to) and
//! [`validate_record_for_read`] on the read path (witness-gated). Both emit a
//! [`crate::audit::SubstrateAuditEvent::MalformedRecordRejected`] on violation.

use std::marker::PhantomData;
use std::time::SystemTime;

use crate::audit::{MalformedRecordReason, SubstrateAuditEvent, SubstrateAuditSink};
use crate::authority::v1::ViewPrivate;
use crate::authority::BoundUserProof;
use crate::identity::TraceId;
use crate::proto::{Did, Nsid};
use crate::sealed;

/// Read-pipeline stage label, for audit/denial reporting symmetry with the
/// bind-side [`crate::authority::PipelineStage`]. The ordered read stages are
/// audience check → content validation → decode; the *placement* of the latter
/// two after the audience check is enforced structurally by
/// [`ReadAuthorization`], not by this label.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadPipelineStage {
    /// §4.5 audience-oracle authorization — produces [`ReadAuthorization`].
    AudienceCheck,
    /// §5.4 / rev6 §4.2 structural validation ([`validate_record`]).
    ContentValidation,
    /// §8.3 content decode.
    Decode,
}

/// Unforgeable witness that the §4.3 / §4.5 audience-oracle check authorized a
/// read.
///
/// **Structural, not data-carrying.** The load-bearing part is the
/// `PhantomData<crate::sealed::Token>`: no consumer outside the crate can build
/// one, so any function requiring `&ReadAuthorization` is compile-time
/// guaranteed to run downstream of a successful read authorization. The reader
/// DID is carried for the convenience of downstream stages (so they need not
/// re-derive it from the proof), but the type's *purpose* is the lock, not the
/// payload.
///
/// The only constructor is [`ReadAuthorization::from_view_private`]: it is
/// derived from a bound `ViewPrivate` proof, which the §4.3 pipeline produces
/// only after the §4.5 audience-oracle check. This ties the witness to the real
/// authorization check — no audience logic is duplicated here.
#[derive(Debug, Clone)]
pub struct ReadAuthorization {
    reader: Did,
    _token: PhantomData<sealed::Token>,
}

impl ReadAuthorization {
    /// Derive a read authorization from a bound `ViewPrivate` proof — evidence
    /// that the §4.3 pipeline (including the §4.5 audience-oracle check)
    /// authorized this reader for the private resource. The reader DID is taken
    /// from the proof. This is the only (non-test) constructor.
    #[must_use]
    pub fn from_view_private(proof: &BoundUserProof<'_, ViewPrivate>) -> Self {
        ReadAuthorization {
            reader: proof.requester().clone(),
            _token: PhantomData,
        }
    }

    /// The authorized reader's DID.
    #[must_use]
    pub fn reader(&self) -> &Did {
        &self.reader
    }

    /// Test-only constructor (the sealed token is otherwise unconstructible).
    #[cfg(test)]
    pub(crate) fn new_for_test(reader: Did) -> Self {
        ReadAuthorization {
            reader,
            _token: PhantomData,
        }
    }
}

/// Structural-validation input: the field-presence view of a private-tier
/// record, decoupled from the codegen `Main` types so a host can build it from
/// whatever record representation it holds.
///
/// `#[non_exhaustive]`; construct via [`RecordValidation::post_private`] /
/// [`RecordValidation::audience`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordValidation {
    /// `tools.kryphocron.feed.postPrivate` field presence.
    PostPrivate {
        /// Whether `text` is present.
        has_text: bool,
        /// Whether `encodedContent` is present.
        has_encoded_content: bool,
        /// Whether `encodedContentCodec` is present.
        has_encoded_content_codec: bool,
        /// Whether `encodedContentGeneration` is present.
        has_encoded_content_generation: bool,
    },
    /// `tools.kryphocron.policy.audience` mode + members presence.
    Audience {
        /// `mode == "list"` (absent reads as `list` per the lexicon).
        mode_is_list: bool,
        /// Whether the `members` array is present. Only consulted when
        /// `mode_is_list` is `true` — the conditional-required rule binds
        /// `members` to list mode only; under any non-list mode this flag
        /// is unconstrained.
        ///
        /// Presence is the substrate's only concern: it checks that
        /// `members` *exists*, not its contents. Interpreting presence —
        /// typically `Some(non-empty)`; whether `Some([])` (an explicitly
        /// empty audience) is meaningful is host policy — lives above this
        /// seam. `ListModeWithoutMembers` fires exactly when this bool is
        /// `false` under list mode.
        has_members: bool,
    },
}

impl RecordValidation {
    /// A `feed.postPrivate` validation input.
    #[must_use]
    pub fn post_private(
        has_text: bool,
        has_encoded_content: bool,
        has_encoded_content_codec: bool,
        has_encoded_content_generation: bool,
    ) -> Self {
        RecordValidation::PostPrivate {
            has_text,
            has_encoded_content,
            has_encoded_content_codec,
            has_encoded_content_generation,
        }
    }

    /// A `policy.audience` validation input.
    #[must_use]
    pub fn audience(mode_is_list: bool, has_members: bool) -> Self {
        RecordValidation::Audience {
            mode_is_list,
            has_members,
        }
    }
}

/// The pure §5.4 / rev6 §4.2 structural rules. Returns the first violated rule,
/// or `Ok(())`.
///
/// `feed.postPrivate`: exactly one of `text` | `encodedContent` (the XOR), plus
/// the orphan-metadata rules (`encodedContent` needs a codec; encoded-side
/// stamps without `encodedContent`, or alongside `text`, are rejected).
/// `policy.audience`: `mode == "list"` requires `members`.
///
/// # Errors
///
/// The first violated [`MalformedRecordReason`].
pub fn validate_record(input: &RecordValidation) -> Result<(), MalformedRecordReason> {
    use MalformedRecordReason as R;
    match *input {
        RecordValidation::PostPrivate {
            has_text,
            has_encoded_content,
            has_encoded_content_codec,
            has_encoded_content_generation,
        } => {
            // XOR (text | encodedContent).
            if has_text && has_encoded_content {
                return Err(R::BothTextAndEncodedContent);
            }
            if has_encoded_content {
                // Encoded path: a codec stamp is required; generation optional.
                if !has_encoded_content_codec {
                    return Err(R::EncodedContentWithoutCodec);
                }
                return Ok(());
            }
            if has_text {
                // Plaintext path: no encoded-side stamps allowed. The codec
                // orphan covers both text-present and text-absent cases.
                if has_encoded_content_codec {
                    return Err(R::EncodedContentCodecWithoutEncodedContent);
                }
                if has_encoded_content_generation {
                    return Err(R::TextWithEncodedContentGeneration);
                }
                return Ok(());
            }
            // Neither text nor encodedContent: any encoded-side stamp is an
            // orphan; otherwise the record is empty.
            if has_encoded_content_codec {
                return Err(R::EncodedContentCodecWithoutEncodedContent);
            }
            if has_encoded_content_generation {
                return Err(R::EncodedContentGenerationWithoutEncodedContent);
            }
            Err(R::NeitherTextNorEncodedContent)
        }
        RecordValidation::Audience {
            mode_is_list,
            has_members,
        } => {
            if mode_is_list && !has_members {
                return Err(R::ListModeWithoutMembers);
            }
            Ok(())
        }
    }
}

/// Write-path structural validation (rev6 §4.2 layer 2). No witness — a write
/// has no upstream authorization stage to defer to. On violation, emits
/// [`SubstrateAuditEvent::MalformedRecordRejected`] and returns the reason.
///
/// # Errors
///
/// The first violated [`MalformedRecordReason`].
pub fn validate_record_for_write(
    input: &RecordValidation,
    nsid: Nsid,
    requester: Did,
    trace_id: TraceId,
    sink: &dyn SubstrateAuditSink,
    at: SystemTime,
) -> Result<(), MalformedRecordReason> {
    validate_record(input).inspect_err(|&reason| {
        emit_rejected(sink, trace_id, nsid, requester, reason, at);
    })
}

/// Read-path structural validation (rev6 §4.2 / §6.4). **Requires
/// [`ReadAuthorization`]** — by type, this cannot be called before the §4.5
/// audience-oracle check, so the emitted
/// [`SubstrateAuditEvent::MalformedRecordRejected`] opens no enumeration channel
/// to unauthorized readers. The requester recorded is the witness's reader DID.
///
/// # Errors
///
/// The first violated [`MalformedRecordReason`].
pub fn validate_record_for_read(
    authz: &ReadAuthorization,
    input: &RecordValidation,
    nsid: Nsid,
    trace_id: TraceId,
    sink: &dyn SubstrateAuditSink,
    at: SystemTime,
) -> Result<(), MalformedRecordReason> {
    validate_record(input).inspect_err(|&reason| {
        emit_rejected(sink, trace_id, nsid, authz.reader().clone(), reason, at);
    })
}

fn emit_rejected(
    sink: &dyn SubstrateAuditSink,
    trace_id: TraceId,
    nsid: Nsid,
    requester: Did,
    reason: MalformedRecordReason,
    at: SystemTime,
) {
    // Fire-and-forget, consistent with the at-rest content seams (§4.9
    // fail-closed-on-audit is the §4.3 bind path's discipline, not this one).
    let _ = sink.record(SubstrateAuditEvent::MalformedRecordRejected {
        trace_id,
        nsid,
        requester,
        reason,
        at,
    });
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::audit::AuditError;

    fn pp(text: bool, ec: bool, codec: bool, generation: bool) -> RecordValidation {
        RecordValidation::post_private(text, ec, codec, generation)
    }

    #[test]
    fn post_private_valid_records_pass() {
        // Plaintext.
        assert!(validate_record(&pp(true, false, false, false)).is_ok());
        // Encoded with codec, no generation.
        assert!(validate_record(&pp(false, true, true, false)).is_ok());
        // Encoded with codec + generation.
        assert!(validate_record(&pp(false, true, true, true)).is_ok());
    }

    #[test]
    fn post_private_every_reason_is_reachable() {
        use MalformedRecordReason as R;
        assert_eq!(validate_record(&pp(true, true, false, false)), Err(R::BothTextAndEncodedContent));
        assert_eq!(validate_record(&pp(false, false, false, false)), Err(R::NeitherTextNorEncodedContent));
        assert_eq!(validate_record(&pp(false, true, false, false)), Err(R::EncodedContentWithoutCodec));
        // codec orphan on plaintext AND on the empty record.
        assert_eq!(validate_record(&pp(true, false, true, false)), Err(R::EncodedContentCodecWithoutEncodedContent));
        assert_eq!(validate_record(&pp(false, false, true, false)), Err(R::EncodedContentCodecWithoutEncodedContent));
        // generation orphan on plaintext vs on the empty record.
        assert_eq!(validate_record(&pp(true, false, false, true)), Err(R::TextWithEncodedContentGeneration));
        assert_eq!(validate_record(&pp(false, false, false, true)), Err(R::EncodedContentGenerationWithoutEncodedContent));
    }

    #[test]
    fn audience_members_rule() {
        use MalformedRecordReason as R;
        assert_eq!(
            validate_record(&RecordValidation::audience(true, false)),
            Err(R::ListModeWithoutMembers)
        );
        assert!(validate_record(&RecordValidation::audience(true, true)).is_ok());
        assert!(validate_record(&RecordValidation::audience(false, false)).is_ok());
    }

    #[derive(Default)]
    struct CapturingSubstrateSink {
        events: Mutex<Vec<SubstrateAuditEvent>>,
    }

    impl SubstrateAuditSink for CapturingSubstrateSink {
        fn record(&self, event: SubstrateAuditEvent) -> Result<(), AuditError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn sample_did() -> Did {
        Did::new("did:plc:exampleexampleexample").unwrap()
    }

    #[test]
    fn validate_for_write_emits_on_violation_no_emit_on_ok() {
        let sink = CapturingSubstrateSink::default();
        let nsid = Nsid::new("tools.kryphocron.feed.postPrivate").unwrap();
        let now = SystemTime::now();
        // Violation emits.
        let err = validate_record_for_write(
            &pp(true, true, false, false),
            nsid.clone(),
            sample_did(),
            TraceId::from_bytes([1; 16]),
            &sink,
            now,
        )
        .unwrap_err();
        assert_eq!(err, MalformedRecordReason::BothTextAndEncodedContent);
        assert!(matches!(
            sink.events.lock().unwrap().as_slice(),
            [SubstrateAuditEvent::MalformedRecordRejected { .. }]
        ));
        // Valid record does not emit.
        let sink2 = CapturingSubstrateSink::default();
        validate_record_for_write(
            &pp(true, false, false, false),
            nsid,
            sample_did(),
            TraceId::from_bytes([1; 16]),
            &sink2,
            now,
        )
        .unwrap();
        assert!(sink2.events.lock().unwrap().is_empty());
    }

    #[test]
    fn validate_for_read_uses_witness_reader_as_requester() {
        let sink = CapturingSubstrateSink::default();
        let reader = sample_did();
        let authz = ReadAuthorization::new_for_test(reader.clone());
        let err = validate_record_for_read(
            &authz,
            &pp(false, false, false, false),
            Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            TraceId::from_bytes([2; 16]),
            &sink,
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err, MalformedRecordReason::NeitherTextNorEncodedContent);
        let events = sink.events.lock().unwrap();
        let SubstrateAuditEvent::MalformedRecordRejected { requester, .. } = &events[0] else {
            panic!("expected MalformedRecordRejected");
        };
        assert_eq!(requester, &reader);
    }
}
